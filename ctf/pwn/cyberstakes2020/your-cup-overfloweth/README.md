# Your Cup Overfloweth

This is a standard buffer overflow vulnerability with a `RWX` stack. Using
`ropper`, we find a `jmp rsp` gadget that allows us to jump into our shellcode
placed directly after the overwritten `RIP`.

The buffer overflow vulnerability can be found in `read_input`. `read_input`
reads input from `stdin` until a newline character or null `00` character is
encountered. Otherwise, an unbounded number of characters can be read into the
stack, overwriting sensitive stack information.
