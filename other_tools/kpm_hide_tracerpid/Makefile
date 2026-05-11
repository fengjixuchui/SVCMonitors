ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = -Wall -O2 -fno-pic -fno-stack-protector \
         -nostdlib -nostdinc -ffreestanding \
         -fno-builtin \
         -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove -fno-builtin-memcmp \
         -mgeneral-regs-only \
         $(INCLUDE_FLAGS)

LDFLAGS = -nostdlib -r

objs := hide_tracerpid.o

all: hide_tracerpid.kpm

hide_tracerpid.kpm: $(objs)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
