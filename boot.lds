OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_header)
SECTIONS
{
  /* start the the beginning our relocated block, where Discharge will place us */
  . = 0x80100000;

	. = ALIGN(4);
	.text : {
    PROVIDE(bfstub_start = .);
		start.o	(.text)
		*(.text)
	}

	. = ALIGN(8);
	.rodata : {
		*(SORT_BY_ALIGNMENT(SORT_BY_NAME(.rodata*)))
	}

	. = ALIGN(8);
	.data : {
		*(.data)
	}

	/* Uninitialised data */
	. = ALIGN(8);
	PROVIDE(lds_bss_start = .);
	.bss (NOLOAD) : {
		*(.bss) . = ALIGN(8);
	}
	PROVIDE(lds_bss_end = .);

  /* EL2 stack */
  . = ALIGN(16);
  . += 0x10000; /* 64 KiB stack */
  el2_stack_end = .;


  /* EL1 stack */
  . = ALIGN(16);
  . += 0x10000; /* 64 KiB stack */
  el1_stack_end = .;

  bfstub_end = .;

	/DISCARD/ : { *(.dynstr*) }
	/DISCARD/ : { *(.dynamic*) }
	/DISCARD/ : { *(.plt*) }
	/DISCARD/ : { *(.interp*) }
	/DISCARD/ : { *(.gnu*) }
}
