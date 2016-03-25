
# Use our cross-compile prefix to set up our basic cross compile environment.
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

# Pull in information about our "hosted" libfdt.
include lib/fdt/Makefile.libfdt

# Allow user of our libraries.
VPATH = .:lib:lib/fdt

# Specify the subimage to be integrated into discharge,
# without the fit extension.
SUBIMAGE = subimage
SUBIMAGE_COMPONENTS = \
	subimage/xen \
	subimage/xen.dts \
	subimage/Image
SUBIMAGE_PADDING = 0

# Build the discharge binary.
TARGET = discharge
OBJS = \
	start.o \
	main.o \
	microlib.o \
	printf.o \
	memmove.o \
	cache.o \
	image.o \
	$(LIBFDT_OBJS)

CFLAGS = \
  -Iinclude \
	-Ilib/fdt \
	-march=armv8-a \
	-mlittle-endian \
	-fno-stack-protector \
	-mgeneral-regs-only \
	-fno-common \
	-fno-builtin \
	-ffreestanding \
	-std=gnu99 \
	-Werror \
	-Wall

LDFLAGS =

%.o: %.S
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

$(TARGET).fit: $(TARGET).bin $(TARGET).its $(SUBIMAGE).fit
	dtc -I dts -O dtb $(TARGET).its > $(TARGET).fit

$(SUBIMAGE).fit: subimage/$(SUBIMAGE).its $(SUBIMAGE_COMPONENTS)
	cd subimage; dtc -p $(SUBIMAGE_PADDING) -I dts -O dtb $(SUBIMAGE).its > ../$(SUBIMAGE).fit; cd ..

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -v -O binary $< $@

$(TARGET).elf: $(OBJS)
	$(LD) -T boot.lds $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o $(TARGET) $(TARGET).bin $(TARGET).elf $(TARGET).fit

.PHONY: all clean
