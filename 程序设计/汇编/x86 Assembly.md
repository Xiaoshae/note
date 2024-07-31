# x86 Assembly

 NASM (Netwide Assembler) 的语法格式，是一种流行的 x86 和 x86-64 汇编器。



# Registers

x86 处理器有 8 个 32 bit 寄存器

![img](./images/x86 Assembly.assets/x86-registers.png)



## ABCD 通用寄存器

`EAX`、`EBX`、`ECX`和`EDX`是通用寄存器（General-Purpose Registers）

- **eax** (Accumulator Register): 这个寄存器经常被用作累加器，还经常用来存放函数的返回值。
- **ebx** (Base Register): 一些约定中，它是“非保留”的，意味着调用者可以修改它而不必担心破坏调用链。
- **ecx** (Count Register): 主要用于循环指令（如`loop`）中的计数器。
- **edx** (Data Register): 通常用于存放第二个操作数，它也可以用于其他类型的数据操作。



`EAX`, `EBX`, `ECX`, `EDX` 四个寄存器，可以再将 32bit 划分成多个子寄存器， 每个子寄存器有专门的名字。

例如 `EAX` 的高 16bit 叫 `AX`（去掉 E, E 大概表示 **Extended**）,低 8bit 叫 `AL` (**Low**）, 8-16bit 叫 `AH` （**High**）。

在汇编语言中，这些寄存器的名字是**大小写无关**的，既可以用 `EAX`，也可以写 `eax`。



**注：寄存器名字是早期计算机历史上流传下来的。例如，EAX 表示 Accumulator，因为它用作算术运算的累加器，ECX 表示 Counter，用来存储循环变量（计数）。但是大部分寄存器的名字已经失去了原来的意义。**





## ESI EDI 变址寄存器

通常用于字符串操作和数据块的复制等任务中。这些寄存器的主要用途如下：

- **esi** (Extended Source Index): 通常用于指向源数据的起始地址。
- **edi** (Extended Destination Index): 通常用于指向目标数据的起始地址。



```
global _start

section .data
    src db 'Hello, World!',0x0a, 0
    dest times 15 db 0

section .text

_start:
    ; 初始化寄存器
    mov esi, src      ; 设置源字符串的地址
    mov edi, dest     ; 设置目标字符串的地址
    mov ecx, 14       ; 字符串长度（不包括结束符）
    
    rep movsb         ; 复制字符串
    
    mov eax, 4
    mov ebx, 1
    mov ecx, dest
    mov edx, 14
    int 0x80
    
    mov eax, 1
    mov ebx, 0
    int 0x80
```



`rep movsb` 是一条x86汇编语言指令，用于重复执行字符串操作。

**指令解释**：

- **rep**: 表示重复执行接下来的字符串操作指令，直到计数器（通常是`ecx`寄存器，在32位模式下；或`rcx`寄存器，在64位模式下）减至0为止。
- **movsb**: 是一个单字节移动指令，它从源地址（由`esi`寄存器指向）读取一个字节，并将其写入目标地址（由`edi`寄存器指向）。同时，它会自动更新`esi`和`edi`寄存器的值，使其指向下一个字节。



`rep movsb` 指令本身不会直接控制复制的方向（前向或后向），但它会根据方向标志（Direction Flag, DF）的状态来确定如何更新源和目标指针。

默认情况下，DF 清零（0）时，`movsb` 指令向前移动（递增）源和目标指针；当 DF 设置为 1 时，它向后移动（递减）这些指针。

- `cld`（Clear Direction Flag）指令将 DF 清零，使复制向前进行。
- `std`（Set Direction Flag）指令将 DF 设置为 1，使复制向后进行。



## ESP EBP

`esp` 寄存器是堆栈指针（Stack Pointer），它总是指向当前堆栈顶部的位置。

`ebp` 寄存器是基址指针（Base Pointer），它指向当前函数调用帧的底部。



## EIP 指令寄存器

**注：在 x86-64 架构中，EIP 被扩展为 64 位，并重命名为 RIP（R15 Instruction Pointer）。**



EIP（Extended Instruction Pointer）是 x86 架构中的一个寄存器。

EIP 用于存储当前指令的地址，每当 CPU 执行完一条指令后，EIP 通常会自动递增到下一条指令的地址，从而控制程序的流程。



EIP寄存器不能使用 移动、加法、减法 等操作来更改，而是使用跳转操作来更改。



### jmp

jmp 将程序控制转移到指令流中的不同点，而不记录返回信息。

操作数指定要跳转到的指令的地址，此操作数可以是即时值、通用寄存器或内存位置。

```
global  _start

section .data
	adrs dd 0  ; 初始化为 0，稍后我们将把 skip 的地址存入这个位置

section .text
_start:
    mov ebx, 42
    mov eax, 1
    jmp skip
    
   ;jmp 0x00000000
   
   ;mov ecx,skip
   ;jmp ecx
   
   ;lea ecx, [skip]  ; 将 skip 标签的地址加载到 ecx 寄存器
   ;mov [adrs], ecx  ; 将 skip 的地址存入 adrs
   ;jmp [adrs]        ; 从 adrs 中读取地址，并跳转到该地址
   
    mov ebx, 13
skip:
    int 0x80
```



**扩展：条件转移指令参考 "EFLAG 标志寄存器" 部分**



##  EFLAG 标志寄存器

注：标志寄存器的名称在不同位CPU中有区别，16位为**FLAG**，32位为**EFLAG**，64位为**RFLAG**。



EFLAG寄存器用途，灰色位保留。

![img](./images/x86 Assembly.assets/f547c67fe9d872479f36f761f94b8a34.png)

**注：FLAG（16位）前16位与EFLAG一致；RFLAG（64位）前32位与EFLAG一致，后32位保留。**



### ZF

ZF是零标志位。它记录相关指令执行后，其结果是否为0。

- 如果计算结果为0，那么zf=1;
- 如果计算结果不为0，那么zf=0。



### PF

PF 是奇偶标志位。它记录相关指令执行后，其结果的所有 bit 位中 1的个数是否为偶数。

- 如果1的个数为偶数，pf=1；
- 如果1的个数为奇数，pf=0。



### SF

SF 是符号标志位。它记录相关指令执行后，其结果是否为负。

- 如果结果为负，sf=1;
- 如果结果非负，sf=0。



00000001B，可以看作为无符号数1，或有符号数+1;

10000001B，可以看作为无符号数129，也可以看作有符号数-127。



例1：

同一个二进制数据，计算机可以将它当作无符号数据来运算，也可以当作有符号数据来运算。比如:

```
mov al,10000001B
add al,1
```

结果：(al)=10000010B。

将 add 指令进行的运算当作**无符号数**的运算，那么 add 指令相当于计算 129+1,结果为 130(10000010B);

将 add 指令进行的运算当作**有符号数**的运算，那么 add 指令相当于计算-127+1，结果为-126(10000010B)。



例2：

```
mov al,10000001B
add al,01111111B
```

执行后，结果为 0，sf=0，表示：如果指令进行的是有符号数运算，那么结果为非负。



不管我们如何看待，CPU 在执行 add 等指令的时候，就已经包含了两种含义，也将得到用同一种信息来记录的两种结果。关键在于我们的程序需要哪一种结果。



### CF

CF 标志表示最近一次算术或逻辑操作是否产生了进位或借位。

- 当进行无符号加法时，如果最高有效位（MSB）产生了进位，则 CF 被置为 1；如果没有产生进位，则 CF 保持为 0。

  ```
  MOV EAX, 0xFFFFFFFF ; EAX = -1 (无符号为 4294967295)
  ADD EAX, 1          ; EAX + 1 = 0 (产生进位)
  ; 此时 CF = 1
  ```

- 当进行无符号减法时，如果 MSB 需要向更高位借位，则 CF 被置为 1；如果没有借位，则 CF 保持为 0。

  ```
  MOV EAX, 1
  SUB EAX, 2          ; EAX - 2 = -1 (无符号为 4294967295, 需要借位)
  ; 此时 CF = 1
  ```

  

### OF

OF 标志表示最近一次算术操作（通常是加法或减法）是否产生了带符号整数溢出。

- 当进行**带符号加法**时，如果正数加上正数的结果变成了负数，或者负数加上负数的结果变成了正数，则 OF 被置为 1；否则，OF 保持为 0。
- 当进行**带符号减法**时，如果正数减去负数的结果变成了负数，或者负数减去正数的结果变成了正数，则 OF 被置为 1；否则，OF 保持为 0。



### cmp

cmp 是比较指令，cmp的功能相当于减法指令，只是不保存结果。cmp指令执行后，将对标志寄存器产生影响。



### 条件转移指令

简化版本

| 指令 | 描述       | 有符号/无符号 | 检查的条件        |
| ---- | ---------- | ------------- | ----------------- |
| JE   | 当相等时   |               | ZF = 1            |
| JNE  | 当不等时   |               | ZF = 0            |
| JB   | 当小于     | 无符号        | CF = 1            |
| JNB  | 当大于等于 | 无符号        | CF = 0            |
| JA   | 当大于     | 无符号        | CF = 0 且 ZF = 0  |
| JNA  | 当小于等于 | 无符号        | CF = 1 或 ZF = 1  |
| JL   | 当小于     | 有符号        | SF ≠ OF           |
| JNL  | 当大于等于 | 有符号        | SF = OF           |
| JG   | 当大于     | 有符号        | ZF = 0 且 SF = OF |
| JNG  | 当小于等于 | 有符号        | ZF = 1 或 SF ≠ OF |



这些指令比较常用，它们都很好记忆，它们的第一个字母都是j，表示jump；后面的字母表示意义如下。

```
e:  表示 equal
ne: 表示 not equal
b:  表示 below
nb: 表示 not below
a:  表示 above
na: 表示 not above
l:  表示 less
nl: 表示 not less
g:  表示 greater
ng: 表示 not greater
```



完整版本

| 指令                 | 描述                                      | 有符号/无符号 | 检查的条件                   |
| -------------------- | ----------------------------------------- | ------------- | ---------------------------- |
| JO                   | 当发生溢出时跳转                          |               | OF = 1                       |
| JNO                  | 当没有发生溢出时跳转                      |               | OF = 0                       |
| JS                   | 当符号为负时跳转                          | 有符号        | SF = 1                       |
| JNS                  | 当符号为非负时跳转                        | 有符号        | SF = 0                       |
| JE / JZ              | 当相等时/当零时跳转                       |               | ZF = 1                       |
| JNE / JNZ            | 当不等时/当非零时跳转                     |               | ZF = 0                       |
| JP / JPE             | 当具有偶数位奇偶性时/当偶数位奇偶性时跳转 |               | PF = 1                       |
| JNP / JPO            | 当具有奇数位奇偶性时/当奇数位奇偶性时跳转 |               | PF = 0                       |
| JCXZ / JECXZ / JRCXZ | 当 CX/ECX/RCX 为零时跳转                  |               | CX = 0<br>ECX = 0<br>RCX = 0 |
| JB / JNAE / JC       | 当低于/当不大于或等于/当进位时跳转        | 无符号        | CF = 1                       |
| JNB / JAE / JNC      | 当不低于/当大于或等于/当没有进位时跳转    | 无符号        | CF = 0                       |
| JBE / JNA            | 当低于或等于/当不大于时跳转               | 无符号        | CF = 1 或 ZF = 1             |
| JA / JNBE            | 当高于/当不小于或等于时跳转               | 无符号        | CF = 0 且 ZF = 0             |
| JL / JNGE            | 当小于/当不大于或等于时跳转               | 有符号        | SF ≠ OF                      |
| JGE / JNL            | 当大于或等于/当不小于时跳转               | 有符号        | SF = OF                      |
| JLE / JNG            | 当小于或等于/当不大于时跳转               | 有符号        | ZF = 1 或 SF ≠ OF            |
| JG / JNLE            | 当大于/当不小于或等于时跳转               | 有符号        | ZF = 0 且 SF = OF            |



# NASM

## global

`global` 指令用于声明一个或多个全局符号。这些符号可以在链接阶段被其他模块引用。

在 NASM 中，`global` 指令通常用于标记程序的入口点（例如 `_start`），及其他需要在整个程序或链接单元中可见的函数或变量。



## section

**section** 指令用于定义一个段（section），它是程序的一部分，具有特定的属性和用途。常见的段有 `.text`、`.data` 和 `.bss`。	

**用途**：

- **代码段**：`.text` 段包含可执行代码。
- **数据段**：`.data` 段包含初始化的数据。
- **未初始化数据段**：`.bss` 段包含未初始化的数据或零填充的数据。



```
global _start
section .text
_start:
    ; 可执行代码放在这里
```



# 段



## .text



## .data

`.DATA` 声明静态数据区。

数据类型修饰原语：

- `DB`: Byte		        1 Bytes
- `DW`: Word      	        2 Bytes
- `DD`: Double Word	4 Bytes



例子：单个变量，指向一个值

```
section .data
var     DB 64    ; 声明一个字节值，称为位置 var，包含值 64。
var2    DB ?     ; 声明一个未初始化的字节值，称为位置 var2。
        DB 10    ; 声明一个没有标签的字节值，包含值 10。它的位置是 var2 + 1。
X       DW ?     ; 声明一个 2 字节未初始化的值，称为位置 X。
Y       DD 30000 ; 声明一个 4 字节值，称为位置 Y，初始化为 30000。
```



例子：数组，指向第一个值的地址

```
section .data
Z       DD 1, 2, 3      ; 声明 3 个 4 字节的值，初始化为 1、2 和 3。位置 Z + 8 的值将是 3。
bytes   DB 10 DUP(?)    ; 声明 10 个未初始化的字节，从位置 bytes 开始。
arr     DD 100 DUP(0)   ; 声明 100 个 4 字节的单词，从位置 arr 开始，全部初始化为 0。
str     DB 'hello',0    ; 声明 6 个字节，从地址 str 开始，初始化为 "hello" 和空字符 (0)。
```



## .bss





# 内存寻址 (Addressing Memory)

有多个指令可以用于内存寻址

`MOV` 将在内存和寄存器之 间移动数据，接受两个参数：第一个参数是目的地，第二个是源。



合法寻址的例子：

```
mov eax, [ebx]        ; 将位于 EBX 所指向的内存地址中的 4 个字节的数据移动到 EAX 中
mov [var], ebx        ; 将 EBX 中的内容移动到由一个 32 位常量 var 指定的内存地址处
mov eax, [esi-4]      ; 将位于 ESI 地址减去 4 的内存位置中的 4 个字节的数据移动到 EAX 中
mov [esi+eax], cl     ; 将 CL 中的内容移动到 ESI 加上 EAX 值所指向的内存地址的一个字节处
mov edx, [esi+4*ebx]  ; 将位于 ESI 加上 EBX 的值乘以 4 所指向的内存地址中的 4 个字节的数据移动到 EDX 中
```



**非法寻址**的例子：

```
mov eax, [ebx-ecx]      ; 只能对寄存器的值相加，不能相减
mov [eax+esi+edi], ebx  ; 最多只能有 2 个寄存器参与地址计算
```



修饰**指针**类型：

- `BYTE PTR` -   1  Byte
- `WORD PTR` -   2  Bytes
- `DWORD PTR` - 4  Bytes

```
mov BYTE PTR [ebx], 2   ; 将数字 2 移动到 EBX 所指向的单个字节中。
mov WORD PTR [ebx], 2   ; 将数字 2 的 16 位整数表示形式移动到从 EBX 所指向的地址开始的两个字节中。
mov DWORD PTR [ebx], 2  ; 将数字 2 的 32 位整数表示形式移动到从 EBX 所指向的地址开始的四个字节中。
```



## 堆栈

在 x86 架构中，堆栈是一个遵循“后进先出”(LIFO) 原则的内存区域。堆栈通常用于保存函数调用时的返回地址、局部变量以及传递给函数的参数等。



`ESP`（Extended Stack Pointer）寄存器是用于管理程序堆栈的寄存器。

- `ESP` 寄存器总是指向堆栈的顶部，也就是最近压入堆栈的值所在的地址。
- 堆栈通常是从高地址向低地址增长的（向下生长）
- 每次压入堆栈时，`ESP` 的值都会减少；而每次从堆栈中弹出值时，`ESP` 的值都会增加。



在 x86 汇编语言中，`PUSH POP` 指令默认操作的是 32 位的数据，即一个完整的双字（DWORD）。

- **PUSH** 指令：当使用 `PUSH` 指令时，`ESP` 的值减少 4（对于 32 位架构），然后将值写入堆栈。

  ```
  push eax
  ```

- **POP** 指令：当使用 `POP` 指令时，从堆栈中弹出一个值，并将 `ESP` 的值增加 4。

  ```
  pop ebx
  ```

- **ADD/SUB** 指令：可以直接修改 `ESP` 的值。

  ```
  add esp,4
  sub esp,4
  ```

  

下面是一个使用 `ESP` 寄存器的简单示例：

```
section .data
value dd 0x12345678  ; 定义一个 32 位的常量

section .text
global _start

_start:
    mov eax, value    ; 将 value 的地址加载到 EAX
    push eax          ; 将 EAX 中的值（value 的地址）压入堆栈
    push dword 1234   ; 将 1234 压入堆栈

    ; 此时 ESP 指向堆栈中的下一个空闲位置
    ; 堆栈中的内容依次为 1234 和 value 的地址

    pop ebx           ; 从堆栈中弹出一个值到 EBX，此时应该是 1234
    pop ecx           ; 从堆栈中弹出一个值到 ECX，此时应该是 value 的地址

    ; ESP 指向堆栈顶部，堆栈为空

    ; 结束程序
    mov eax, 1        ; sys_exit 系统调用编号
    xor ebx, ebx      ; 退出状态码为 0
    int 0x80          ; 调用内核
```



# 调用约定

 **调用约定是一个协议，规定了如何调用以及如何从过程返回**。

给定一组 calling convention rules，程序员无需查看子函数的定义就可以确定如何将参数传给它，高级语言编译器只要遵循这些 rules，就可以使得汇编函数和高级语言函数互相调用。

Calling conventions 有多种。我们这里介绍使用最广泛的一种：**C 语言调用约定**（C Language Calling Convention）。遵循这个约定，可以使汇编代码安全地被 C/C++ 调用 ，也可以从汇编代码调用 C 函数库。



C 调用约定:

- 强烈依赖**硬件栈**的支持 (hardwared-supported stack)
- 基于 `push`, `pop`, `call`, `ret` 指令
- 子过程**参数通过栈传递**: 寄存器保存在栈上，子过程用到的局部变量也放在栈上



调用惯例分为两部分。第一部分用于 **调用方**（**caller**），第二部分用于**被调 用方**（**callee**）。



## 调用方规则 (Caller Rules)

在一个子过程调用之前，调用方应该：

1. **保存应由调用方保存的寄存器**（**caller-saved** registers): `EAX`, `ECX`, `EDX`

   这几个寄存器可能会被被调用方（callee）修改，所以先保存它们，以便调用结束后恢复栈的状态。

2. **将需要传给子过程的参数入栈**（push onto stack)

   参数按**逆序** push 入栈（最后一个参数先入栈）。由于栈是向下生长的，第一个参数会被存储在最低地址（**这个特性使得变长参数列表成为可能**）。

3. **使用 `call` 指令，调用子过程(函数）**

   `call` 先将返回地址 push 到栈上，然后开始执行子过程代码。子过程代码需要遵守的 callee rules。

子过程返回后（`call` 执行结束之后），被调用方会将返回值放到 `EAX` 寄存器，调用方可以从中读取。

```
;保存 eax ecx edx
push eax
push ecx
push edx

;参数入栈
push [var] ; 首先推送最后一个参数
push 216 ; 推送第二个参数
push eax ; 最后推送第一个参数

; 调用函数（假设使用 C 命名）
call _myFunc
```



子过程返回后，为恢复机器状态，调用方需要做：

1. **从栈上删除传递的参数**

   栈恢复到准备发起调用之前的状态。

2. **恢复由调用方保存的寄存器**（`EAX`, `ECX`, `EDX`）—— 从栈上 pop 出来

   调用方可以认为，除这三个之外，其他寄存器的值没有被修改过。

```
;删除传递的参数
add esp,12

;恢复寄存器
pop edx
pop ecx
pop eax
```



## 被调用方规则 (Callee Rules)

1. **将寄存器 `EBP` 的值入栈（保存ebp的值），然后 赋值`ESP` 给`EBP`（保存esp的值）**

   ```
   push ebp
   mov  ebp, esp
   ```

2. **在栈上为局部变量分配空间**

   栈自顶向下生长，故随着变量的分配，栈顶指针不断减小。

3. **保存应有被调用方保存（`callee-saved`）的寄存器** —— 将他们压入栈。包括 `EBX`, `EDI`, `ESI`

```
;保存ebp 和 esp的值
push ebp
mov  ebp, esp

;在栈上分配局部变量空间
sub esp,12

;保存 ebx edi esi 寄存器
push ebx
push edi
push esi
```





以上工作完成，就可以执行子过程的代码了。当子过程返回后，必须做以下工作：

1. **将返回值保存在 `EAX`**
2. **恢复应由被调用方保存的寄存器**(`EDI`, `ESI`) —— 从栈上 pop 出来
3. **释放局部变量**
4. **恢复调用方 base pointer `EBP` —— 从栈上 pop 出来**
5. **最后，执行 `ret`，返回给调用方 (caller)**

```
;返回值保存到 eax
mov eax,[返回值]

;恢复 ebx edi esi寄存器
push esi
push edi
push ebx

;释放局部变量 恢复ebp
mov esp,ebp
pop ebp

;返回给调用方
ret
```



## 汇编调用C函数

```
global main

extern printf

section .data
    msg db "Testing %i...", 0x0a, 0x00

section .text
main:
    push ebp
    mov ebp, esp
    
    push 123
    push msg
    call printf
    
    mov eax, 0
    
    mov esp, ebp
    pop ebp
    ret
```

```
nasm -f elf32 ex10.asm -o  ex10.o
gcc -m32 ex10.o -o ex10
```



## C调用汇编函数

add42.asm

```
global  add42

section .text

add42:
    push ebp
    mov  ebp, esp

    mov  eax, [ebp+8]
    add  eax, 42

    mov  esp, ebp
    pop  ebp
    ret
```



main.c

```
#include <stdio.h>

int add42(int x);

int main(void) {

    int x = 20;
    x = add42(20);
    printf("x = %d\n",x);

}
```



terminal

```
nasm -f elf32 add42.asm -o add42.o
gcc -m32 main.c add42.o -o add42
```

