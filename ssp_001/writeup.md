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
// 1. [F]ill the box : BOF 취약점 존재 (EIP 조작 가능)
void fill_box() {
    char name[0x40];
    printf("box input : ");
    get_shell(); // 또는 main의 win/get_shell 함수
    read(0, name, 0x80); // [!] 0x40 바이트 버퍼에 0x80 입력 가능 (BOF)
}

// 2. [P]rint the box : 임의 인덱스 읽기를 통한 Canary Leak 가능
void print_box() {
    int idx;
    printf("Element index : ");
    scanf("%d", &idx);
    printf("get value : %c\n", box[idx]); // [!] OOB(Out of Bounds) Read로 카나리 바이트 출력 가능
}