
# Use our cross-compile prefix to set up our basic cross compile environment.
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

# Pull in information about our "hosted" libfdt.
include lib/fdt/Makefile.libfdt

# Allow user of our libraries.
VPATH = .:lib:lib/fdt

# Build the discharge binary.
TARGET = discharge
OBJS = \
	start.o \
	main.o \
	microlib.o \
	printf.o \
	memmove.o \
	cache.o \
	subimage.o \
	$(LIBFDT_OBJS)

CFLAGS = \
  -Iinclude \
	-Ilib/fdt \
	-march=armv8-a \
	-mlittle-endian \
	-fno-stack-protector \
	-mgeneral-regs-only \
	-mstrict-align \
	-fno-common \
	-fno-builtin \
	-ffreestanding \
	-std=gnu99 \
	-Werror \
	-Wall \
	-ggdb

LDFLAGS =

%.o: %.S
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

$(TARGET).fit: $(TARGET).bin $(TARGET).its
	mkimage -f $(TARGET).its $(TARGET).fit

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -v -O binary $< $@

$(TARGET).elf: $(OBJS)
	$(LD) -T boot.lds $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o $(TARGET) $(TARGET).bin $(TARGET).elf $(TARGET).fit

.PHONY: all clean
