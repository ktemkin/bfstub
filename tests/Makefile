
# Use our cross-compile prefix to set up our basic cross compile environment.
CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

# Pull in information about our "hosted" libfdt.
include ../lib/fdt/Makefile.libfdt

# Allow user of our libraries.
VPATH = .:..:../lib:../lib/fdt

TARGET=test_runner
TESTS = \
	test_microlib.o

# Specify the pieces of discharge that will be used "under test".
OBJS = \
	microlib.o \
	printf.o \
	memmove.o \
	cache.o \
	image.o \
	$(LIBFDT_OBJS)

COMMON_FLAGS = \
	-D__RUNNING_ON_OS__ \
	-I.. \
	-fno-stack-protector \
	-fno-common \
	-fno-builtin \
	-Werror \
	-Wall

CFLAGS = \
	$(COMMON_FLAGS) \
	-Iinclude \
	-I../include \
	-Ilib/fdt \
	-I../lib/fdt \
	-std=gnu99 \
	-ffreestanding \

CXXFLAGS = \
	-D__USE_SYSTEM_HEADERS__ \
	$(COMMON_FLAGS)

LDFLAGS =

all: run_tests

run_tests: $(TARGET)
	./test_runner

$(TARGET): $(TARGET).o $(TESTS) $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@

%.o: %.S
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f *.o $(TARGET) $(TARGET).bin $(TARGET).elf $(TARGET).fit

.PHONY: all clean run_tests
