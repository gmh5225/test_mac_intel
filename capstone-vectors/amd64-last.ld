SECTIONS
{
  .cs_x86_amd64_text : { *(.cs_x86_amd64_text) }
}
INSERT AFTER .fini;

SECTIONS
{
  .cs_x86_amd64_rodata : { *(.cs_x86_amd64_rodata) }
}
INSERT AFTER .eh_frame;
