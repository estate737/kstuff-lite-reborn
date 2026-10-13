#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/cpuset.h>
#include <ps5/kernel.h>

#include "reborn.h"
#include "kdlsym.h"
#include "khook.h"
#include "paging.h"
#include "util.h"
#include "break_hv_payload/break_hv.h"

#define STATE_ARMED 0x4B484F4F4B454401ULL
#define STATE_DONE  0x4B484F4F4B454402ULL
#define COOKIE_VAL  0xCAFE133741414141ULL
#define HV_COOKIE   0xCAFEDEAD00001337ULL
#define HOOK_CORE 0
#define HOOK_IST 6
#define CAVE_STATE_OFF 0x600
#define CAVE_SAVE_OFF 0x620
#define STARTUP_MP_PAYLOAD_PAGE 0x3FFFF000
#define HV_LOADER_PA_REGULAR 0x062800000ULL
#define HV_LOADER_PA_PRO     0x8E0800000ULL

static uint64_t hv_base_pa;

static int install_resume_hook(uint64_t cave, uint64_t cr3)
{
    khook_t hook;
    kh_chain_t chain;
    uint8_t chain_buf[0x800];
    int ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
    if (ret) return ret;
    hook.tss_stride = KH_TSS_STRIDE;
    kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                  kdlsym(KERNEL_SYM_COMMON_TSS));
    kh_set_core(&hook, HOOK_CORE);
    hook.oneshot = 1;
    kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
    kh_set_resume_rsi(&hook, kdldmap(STARTUP_MP_PAYLOAD_PAGE));
    kh_set_resume_rdx(&hook, cr3);

    uint64_t oracle = kh_user_data_addr(&hook);
    kh_chain_init(&chain, chain_buf, sizeof(chain_buf));
    kh_chain_store(&chain, oracle, COOKIE_VAL);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
    kh_chain_q(&chain, cr3);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
    kh_chain_q(&chain, oracle + 8);
    kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);
    kh_chain_memcpy(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE), cave + 0x1000, 0xF00);
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF00),
                   kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF08), kdldmap(0));
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF10), oracle);
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18),
                   hv_base_pa == HV_LOADER_PA_PRO ? hv_base_pa - 0x800000 : hv_base_pa);
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF20),
                   hv_base_pa + rawoff(HV_SYM_HEAP_BASE));
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF28),
                   hv_base_pa + rawoff(HV_SYM_PCPUS));

    ret = kh_install(&hook, &chain);
    if (ret) return ret;
    /* Persist recovery state before arming the hardware breakpoint. */
    if (kwrite(cave + CAVE_SAVE_OFF, &hook.saved_gate_lo, 8) ||
        kwrite(cave + CAVE_SAVE_OFF + 8, &hook.saved_gate_hi, 8) ||
        kwrite(cave + CAVE_SAVE_OFF + 16, &hook.saved_ist, 8) ||
        kwrite(cave + CAVE_STATE_OFF, &(uint64_t){STATE_ARMED}, 8)) {
        kh_restore(&hook);
        return -1;
    }
    kh_trigger(&hook);
    return 0;
}

static int uninstall_hook(uint64_t cave)
{
    khook_t hook;
    int ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
    if (ret) return ret;
    hook.tss_stride = KH_TSS_STRIDE;
    kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                  kdlsym(KERNEL_SYM_COMMON_TSS));
    kh_set_core(&hook, HOOK_CORE);
    hook.saved_gate_lo = kread64(cave + CAVE_SAVE_OFF);
    hook.saved_gate_hi = kread64(cave + CAVE_SAVE_OFF + 8);
    hook.saved_ist = kread64(cave + CAVE_SAVE_OFF + 16);
    hook.installed = 1;
    ret = kh_disarm(&hook);
    if (ret) return ret;
    return kh_restore(&hook);
}

static int update_entry(uint64_t addr, uint64_t value, uint64_t clear, uint64_t set)
{
    if (addr == UINT64_MAX) return -1;
    value = (value & ~clear) | set;
    return kwrite(addr, &value, sizeof(value));
}

static int prepare_page_tables(uint64_t pmap)
{
    uint64_t va = kdldmap(STARTUP_MP_PAYLOAD_PAGE), value = 0, addr;
    const uint64_t nx = 1ULL << PDE_EXECUTE_DISABLE;
    const uint64_t xo = 1ULL << PDE_XOTEXT;
    const uint64_t rw = 1ULL << PDE_RW;
    addr = find_pml4e(pmap, va, &value);
    if (addr == UINT64_MAX || update_entry(addr, value, nx, 0)) return -1;
    addr = find_pdpe(pmap, va, &value);
    if (addr == UINT64_MAX || update_entry(addr, value, nx, 0)) return -1;
    if (!PDE_FIELD(value, PS)) {
        addr = find_pde(pmap, va, &value);
        if (addr == UINT64_MAX || update_entry(addr, value, nx, 0)) return -1;
        if (!PDE_FIELD(value, PS)) {
            addr = find_pte(pmap, va, &value);
            if (addr == UINT64_MAX || update_entry(addr, value, nx, 0)) return -1;
        }
    }

    /* Walk only real leaf mappings, including 1 GiB and 2 MiB pages. */
    for (va = ktext(0); va < (uint64_t)KERNEL_ADDRESS_DATA_BASE; ) {
        uint64_t step;
        addr = find_pdpe(pmap, va, &value);
        if (addr == UINT64_MAX) {
            va += 0x1000;
            continue;
        }
        if (PDE_FIELD(value, PS)) {
            step = 1ULL << 30;
        } else {
            addr = find_pde(pmap, va, &value);
            if (addr == UINT64_MAX) {
                va += 0x1000;
                continue;
            }
            if (PDE_FIELD(value, PS)) {
                step = 1ULL << 21;
            } else {
                addr = find_pte(pmap, va, &value);
                if (addr == UINT64_MAX) {
                    va += 0x1000;
                    continue;
                }
                step = 0x1000;
            }
        }
        if (update_entry(addr, value, xo, rw)) return -1;
        va = (va & ~(step - 1)) + step;
    }
    return 0;
}

int byepervisor_prepare(void)
{
    uint32_t fw = kernel_get_fw_version() & 0xffff0000;
    uint64_t cave, oracle, state, authid, mask[2] = {0}, core0[2] = {1ULL << 15, 0};
    cpusetid_t saved_set;
    int result = -1;
    int fail_code = 0;
    const char *fail_stage = "unknown";

    if (fw != 0x13600000 && fw != 0x13200000 && fw != 0x13000000) {
        notifyf("kstuff Reborn: unsupported firmware %x.%02x", fw >> 24, (fw >> 16) & 0xff);
        return -1;
    }
    cave = kdlsym(KERNEL_SYM_DATA_CAVE);
    oracle = cave + KH_OFF_USER;
    state = kread64(cave + CAVE_STATE_OFF);
    if (state == STATE_DONE && kread64(oracle) == HV_COOKIE) {
        puts("Byepervisor already completed during this boot");
        return 0;
    }
    if (state != 0 && state != STATE_ARMED) {
        notifyf("kstuff Reborn: kernel scratch area is in use; reboot before retrying");
        return -1;
    }

    int soc_id = sceKernelGetMainSocId();
    if (soc_id < 0) return -1;
    hv_base_pa = soc_id == 0x840fd0 ? HV_LOADER_PA_PRO : HV_LOADER_PA_REGULAR;
    printf("Byepervisor firmware=%08x soc=%x HV PA=%lx\n", fw, soc_id, hv_base_pa);
    authid = kernel_get_ucred_authid(getpid());
    if (cpuset_getid(CPU_LEVEL_CPUSET, CPU_WHICH_PID, getpid(), &saved_set) ||
        cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                           sizeof(mask), (cpuset_t *)mask)) return -1;
    if (kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL)) return -1;
    /* Sony's CPU numbering is reversed by util.c (core 0 is mask bit 15).
     * Do not compare sceKernelGetCurrentCpu() with the logical hook index. */
    if (pin_to_core(HOOK_CORE)) {
        fail_stage = "pin";
        fail_code = -1;
        goto out;
    }

    if (state != STATE_ARMED) {
        uint64_t pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
        uint64_t cr3 = kread64(pmap + 0x28);
        if (!cr3 || (cr3 & 0xfff) || break_hv_len > 0x400) {
            fail_stage = "cr3/payload";
            fail_code = -1;
            goto out;
        }
        if (kwrite(cave + 0x1000, break_hv, break_hv_len)) {
            fail_stage = "payload-copy";
            fail_code = -1;
            goto out;
        }
        fail_code = prepare_page_tables(pmap);
        if (fail_code) {
            fail_stage = "page-tables";
            goto out;
        }
        fail_code = install_resume_hook(cave, cr3);
        if (fail_code) {
            fail_stage = "hook-install";
            goto out;
        }
    }
    notifyf("kstuff Reborn: enter Rest Mode, then wake the console. kstuff will continue automatically.");
    for (;;) {
        if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                               sizeof(core0), (const cpuset_t *)core0)) {
            fail_stage = "resume-affinity";
            fail_code = -1;
            goto out;
        }
        uint64_t cookie = kread64(oracle);
        /* The hook's COOKIE_VAL only means it fired. Require the AP payload. */
        if (cookie == HV_COOKIE) break;
        if (cookie != 0 && cookie != COOKIE_VAL) {
            fail_stage = "resume-cookie";
            fail_code = -1;
            goto out;
        }
        sceKernelSleep(1);
    }
    fail_code = uninstall_hook(cave);
    if (fail_code) {
        fail_stage = "hook-remove";
        goto out;
    }
    uint64_t text;
    if (kread(ktext(0), &text, sizeof(text))) {
        fail_stage = "text-read";
        fail_code = -1;
        goto out;
    }
    if (kwrite(cave + CAVE_STATE_OFF, &(uint64_t){STATE_DONE}, 8)) {
        fail_stage = "state-write";
        fail_code = -1;
        goto out;
    }
    printf("Byepervisor ready; kernel text=%016lx. Installing kstuff.\n", text);
    notifyf("kstuff Reborn: hypervisor stage completed. Installing kstuff...");
    result = 0;
out:
    /* kstuff creates worker threads; they must not inherit a core-0-only mask. */
    if (cpuset_setid(CPU_WHICH_PID, getpid(), saved_set)) result = -1;
    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                           sizeof(mask), (const cpuset_t *)mask)) result = -1;
    if (kernel_set_ucred_authid(getpid(), authid)) result = -1;
    if (result) {
        notifyf("kstuff Reborn: failed at %s (%d). Reboot before retrying.",
                fail_stage, fail_code);
    }
    return result;
}
