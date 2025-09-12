/* linker_script.ld */
SECTIONS
{
    . = 0x800000; /* Set the base address */

    .text : {
        *(.text) /* All .text sections from all object files */
    }

    .data : {
        *(.data) /* All .data sections from all object files */
    }

    .bss : {
        *(.bss) /* All .bss sections from all object files */
    }
}
