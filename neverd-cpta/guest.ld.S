#include "CptaGuest.def"
ENTRY(_start)
SECTIONS {
  . = CPA_GUEST_BASE;
  .text : { *(.text.start) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : {
    . = ALIGN(CPA_MACHINE_WORD_BYTES);
    GuestBSSStart = .;
    *(.bss*) *(COMMON)
    . = ALIGN(CPA_MACHINE_WORD_BYTES);
    GuestBSSEnd = .;
  }
}
