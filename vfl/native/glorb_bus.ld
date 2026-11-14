ENTRY(virtual_length)
SECTIONS {
  . = 0x40390000;
  .text : { *(.literal .literal.*) *(.text .text.*) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
