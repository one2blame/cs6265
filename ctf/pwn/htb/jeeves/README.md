# Jeeves

## Description

This is an **easy** `pwn` challenge from Hack the Box, released in 2020. The
results of `checksec` for the binary can be found below:

```bash
[*] './jeeves'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Summary

The binary is designed to teach basic stack buffer overflow techniques. No
canary is present so we don't have to worry about leaking any sensitive stack
information. The only difficult portion of this binary is to make sure to use
the right reverse-engineering tools. When inspecting this target in Binary
Ninja, if using the High Level Intermediate Language (HLIL) view, you'll
completely miss the way to get the flag - like I did.

Inspecting the disassembly of `jeeves` in objdump, like so:

```bash
objdump -M intel -D jeeves
```

and viewing `main()` in the `.text` section will reveal that a stack variable
contained at `$rbp-0x4` is compared to the value `0x1337bab3` - this value is
originally set to `deadc0d3` at the beginning of `main()`. Passing this
comparison, `flag.txt` will be `printf()`'d to the screen.

Again, make sure to inspect further with different tools. The decompilation
provided by Binary Ninja completely ignored this code present in `main()`.
