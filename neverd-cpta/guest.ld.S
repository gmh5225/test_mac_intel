#include "CptaGuest.def"
ENTRY(_start)
SECTIONS {
  . = CPA_GUEST_BASE;
  .text : { *(.text.start) *(.text*) }
  .rodata : { *(.rodata*) }
  . = ALIGN(CPA_PAGE_BYTES);
  GuestDataStart = .;
  .data : { *(.data*) }
  .bss : {
    . = ALIGN(CPA_MACHINE_WORD_BYTES);
    GuestBSSStart = .;
    *(.bss*) *(COMMON)
    . = ALIGN(CPA_MACHINE_WORD_BYTES);
    GuestBSSEnd = .;
  }
  ASSERT(GuestBSSEnd <= CPA_GUEST_BASE + CPA_GUEST_MAP_BYTES,
         CPA_MAP_LIMIT_MESSAGE)
}
