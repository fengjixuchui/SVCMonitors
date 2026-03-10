ifndef TARGET_COMPILE
TARGET_COMPILE = /opt/homebrew/bin/aarch64-none-elf-
endif

ifndef KP_DIR
KP_DIR = ../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := include patch/include linux/include linux/include/uapi linux/arch/arm64/include linux/arch/arm64/include/uapi linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

TARGET = svc-monitor.kpm
objs := svc_monitor.o

all: $(TARGET)

$(TARGET): $(objs)
	$(CC) -r -o $@ $^

svc_monitor.o: src/svc_monitor.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -fno-builtin \
		-fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove -fno-builtin-memcmp \
		-fno-tree-loop-distribute-patterns \
		-o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	rm -f $(objs)
