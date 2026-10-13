#   Copyright (C) 2025 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

LOADER_OPT ?= -O2
CFLAGS += -Wall -Werror
CPPFLAGS += -Iinclude

LDFLAGS += -lz \
           -lSceSystemService \
           -lSceUserService \
           -lSceAppInstUtil \
           -lSceFsInternalForVsh \
           -lsqlite3 \
		   -Wl,-s

# Automatically grab all .c files in src/
SRC := $(shell find src -name '*.c')

all: kstuff.elf

REBORN_DIR := ../byepervisor
REBORN_SRC := $(filter-out $(REBORN_DIR)/khook.c,$(wildcard $(REBORN_DIR)/*.c))
REBORN_OBJ := $(REBORN_DIR)/khook.o
REBORN_HDR := $(REBORN_DIR)/break_hv_payload/break_hv.h

reborn: kstuff-reborn.elf

$(REBORN_HDR): $(REBORN_DIR)/break_hv_payload/break_hv.c $(REBORN_DIR)/break_hv_payload/entry.S $(REBORN_DIR)/break_hv_payload/link.ld $(REBORN_DIR)/break_hv_payload/build.sh
	sh $(REBORN_DIR)/break_hv_payload/build.sh

$(REBORN_OBJ): $(REBORN_DIR)/khook.c $(wildcard $(REBORN_DIR)/include/*.h)
	$(CC) $(CFLAGS) -I$(REBORN_DIR)/include -O0 -fno-omit-frame-pointer -c $< -o $@

kstuff-reborn.elf: ../ps5-kstuff/payload.bin $(SRC) $(REBORN_SRC) $(REBORN_OBJ) $(REBORN_HDR) $(wildcard $(REBORN_DIR)/include/*.h) $(wildcard $(REBORN_DIR)/include/offsets/*.h) include/shellcore_dynlib_abi.h ../lib/r0gdb-bootstrap.h ../lib/shellcore-imports.h
	$(CC) $(CPPFLAGS) -I$(REBORN_DIR)/include $(CFLAGS) $(LOADER_OPT) -DKSTUFF_BYEPERVISOR=1 $(SRC) $(REBORN_SRC) $(REBORN_OBJ) -o $@ $(LDFLAGS)

.FORCE:

../ps5-kstuff/payload.bin: .FORCE
	$(MAKE) -C ../ps5-kstuff/

kstuff.elf: ../ps5-kstuff/payload.bin $(SRC) include/shellcore_dynlib_abi.h ../lib/r0gdb-bootstrap.h ../lib/shellcore-imports.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LOADER_OPT) $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f *.o *.elf
	rm -f $(REBORN_OBJ) $(REBORN_HDR) $(REBORN_DIR)/break_hv_payload/*.o $(REBORN_DIR)/break_hv_payload/*.bin $(REBORN_DIR)/break_hv_payload/*.elf

test: kstuff.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
