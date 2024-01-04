# gdb工具



# gcc -g

如果要使用`gdb`调试程序的话，需要在gcc编译的时候加上`-g`参数，否则调试的时候部分功能无法使用。



没有使用`-g`参数

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gcc -o hello hello.c   #------注意这里------#
gef➤  list
1	./elf/<built-in>: 没有那个文件或目录.

```



使用了`-g`参数

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gcc -g -o hello hello.c  #------注意这里------#

┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb hello              
gef➤  list
1	#include <stdio.h>
2	
3	int main(void){
4	
5		printf("Hello World!\n");
6	
7		return 0;
8	}
gef➤  
```



# gdb调试命令

gdb下的所有调试都可以简写，例如`run`可以简写为`r`



## list

查看程序源代码，注意使用此命令要求程序在`gcc`编译时使用了`-g`参数

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb hello
(gdb) list
1	#include <stdio.h>
2	
3	int main(void){
4	
5		printf("Hello World!\n");
6	
7		return 0;
8	}

```



## run

运行或重新运行程序



### 未设置断点

run命令将整个程序执行一次，不会停止

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb hello                    
(gdb) run
Starting program: /root/Desktop/pwn/hello 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hello World!
[Inferior 1 (process 24744) exited normally]

```



### 设置断点

查看源代码

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb hello

#查看源代码
(gdb) list
1	#include <stdio.h>
2	
3	int main(void){
4	
5		printf("Hello World!\n");
6	
7		return 0;
8	}
```



在第五行设置断点





```
#在第五行设置断点
(gdb) break 5
Breakpoint 1 at 0x113d: file hello.c, line 5.
```



开始运行程序，遇到断点时停止

```
#开始运行程序
(gdb) run
Starting program: /root/Desktop/pwn/hello 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

#遇到断点停了下来
Breakpoint 1, main () at hello.c:5
5		printf("Hello World!\n");
```



再次使用run，程序提醒正在调试的程序已经在运行了，是否重新运行

```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) n
Program not restarted.
```



## break

设置断点

`break [行号]`给指定的C语言设置断点

`break *[地址]`给指定的汇编语言地址设置断点



## next

单步调试执行一条语句



在断定处停止

```
(gdb) run
Starting program: /root/Desktop/pwn/hello 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main () at hello.c:5
5		printf("Hello World!\n");
```



使用next执行一条语句

此时执行的是`printf("Hello World!\n");`语句`return 0;`是下一次使用`next`时将要执行的语句

```
(gdb) next
Hello World!
7		return 0;
```



继续使用`next`执行剩下的语句

```
(gdb) next
8	}
(gdb) next
__libc_start_call_main (main=main@entry=0x555555555139 <main>, argc=argc@entry=1, 
    argv=argv@entry=0x7fffffffe2b8) at ../sysdeps/nptl/libc_start_call_main.h:74
74	../sysdeps/nptl/libc_start_call_main.h: 没有那个文件或目录.
(gdb) next
[Inferior 1 (process 28652) exited normally]
(gdb) 
```



注意：next必须在设置断点后，使用run开始运行程序后才能使用

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb hello
(gdb) next
The program is not being run.
#该程序没有运行。
```



## start

开始单步调试，运行程序，停在mian函数的第一句



查看程序，没有设置断点

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb hello
(gdb) list
1	#include <stdio.h>
2	
3	int main(void){
4	
5		printf("Welcome to GDB tools !\n");
6		printf("by.XiaoshaeCrocodile\n");
7	
8		return 0;
9	}
```



开始单步调试，程序运行停在了第一步

```
(gdb) start
Temporary breakpoint 1 at 0x113d: file hello.c, line 5.
Starting program: /root/Desktop/pwn/hello 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Temporary breakpoint 1, main () at hello.c:5
5		printf("Welcome to GDB tools !\n");
```



注意：

- `start`和`run`一样，只能在程序未运行时使用，如果程序运行后使用`start`会询问是否重新运行函数
- 即使设置了断点start运行程序后，也会停在`mian`函数的第一步



### nexti

执行一条汇编语句



## continue

继续运行直到遇到下一个断点或程序结束



在第五行和第七行设置断点

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb hello
(gdb) break 5
Breakpoint 1 at 0x113d: file hello.c, line 5.
(gdb) break 7
Breakpoint 2 at 0x115b: file hello.c, line 7.
(gdb) list
1	#include <stdio.h>
2	
3	int main(void){
4	
5		printf("one\n");
6		printf("Welcome to GDB tools !\n");
7		printf("two\n");
8		printf("by.XiaoshaeCrocodile\n");
9		printf("Program End\n");
10	
```



开始运行程序，遇到第一个断点

```
(gdb) run
Starting program: /root/Desktop/pwn/hello 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main () at hello.c:5
5		printf("one\n");
```



使用continue继续运行程序，遇到第二个断点

```
(gdb) continue 
Continuing.
one
Welcome to GDB tools !

Breakpoint 2, main () at hello.c:7
7		printf("two\n");
```



使用continue继续运行，直到程序结束

```
(gdb) continue 
Continuing.
two
by.XiaoshaeCrocodile
Program End
[Inferior 1 (process 48744) exited normally]
```



## step

遇到函数使用next命令不会进入函数内部，而使用step命令则会进去函数内部

```c
#include <stdio.h>

void function(void){

	printf("The is Function!\n");
	return ;
}

int main(void){

	printf("Welcome to GDB tools !\n");
	function();

	return 0;
}
```



在function函数调用处设置断点，使用run开始

```
(gdb) run
Starting program: /root/Desktop/pwn/hello 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to GDB tools !

Breakpoint 1, main () at hello.c:12
12		function();
```



使用next执行function函数

```
(gdb) next
The is Function!
14		return 0;
```



使用step进入function函数

```
(gdb) step
function () at hello.c:5
5		printf("The is Function!\n");
(gdb) next
The is Function!
6		return ;
```



使用continue执行到末尾

```
(gdb) continue 
Continuing.
[Inferior 1 (process 56390) exited normally]
```



## finish

执行完函数剩余代码，返回到上一函数



step进入函数

```
(gdb) step
function () at hello.c:5
5		printf("The is Function!\n");
```



finish执行函数剩余代码

```
(gdb) finish 
Run till exit from #0  function () at hello.c:5
The is Function!
main () at hello.c:14
14		return 0;
```



continue执行到函数末尾

```
(gdb) continue 
Continuing.
[Inferior 1 (process 57812) exited normally]
```



注意：

- 函数某一条语句处开始执行finish命令，在返回到上一函数前遇到了断点也会停下来
- finish命令不能在mian函数中使用



## info

查看一些信息的函数



### locals

查看当前函数的局部变量



启动程序

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb add
(gdb) start
Temporary breakpoint 1 at 0x555555555172: file add.c, line 13.
Starting program: /root/Desktop/pwn/add 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Temporary breakpoint 1, main () at add.c:13
13		int x,y,z = 0;
```



执行`int x,y,z`函数后查看局部变量

```
(gdb) next
14		scanf("%d,%d",&x,&y);
(gdb) info locals 
x = -134227280
y = 0
z = 0
```



### function

```
┌──(root㉿kali)-[~/Desktop/pwn]
└─# gdb add
(gdb) info function
All defined functions:

File add.c:
3:	int add(int, int);
11:	int main(void);

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  printf@plt
0x0000000000001040  __isoc99_scanf@plt
0x0000000000001050  __cxa_finalize@plt
0x0000000000001060  _start
0x0000000000001090  deregister_tm_clones
0x00000000000010c0  register_tm_clones
0x0000000000001100  __do_global_dtors_aux
0x0000000000001140  frame_dummy
0x00000000000011d0  _fini
```



### files

显示文件信息

```
(gdb) info files 
Symbols from "/root/Desktop/pwn/add".
Local exec file:
	`/root/Desktop/pwn/add', file type elf64-x86-64.
	Entry point: 0x1060
	0x0000000000000318 - 0x0000000000000334 is .interp
	0x0000000000000338 - 0x0000000000000358 is .note.gnu.property
	0x0000000000000358 - 0x000000000000037c is .note.gnu.build-id
	0x000000000000037c - 0x000000000000039c is .note.ABI-tag
	0x00000000000003a0 - 0x00000000000003c4 is .gnu.hash
	0x00000000000003c8 - 0x0000000000000488 is .dynsym
	0x0000000000000488 - 0x0000000000000530 is .dynstr
	0x0000000000000530 - 0x0000000000000540 is .gnu.version
	0x0000000000000540 - 0x0000000000000580 is .gnu.version_r
	0x0000000000000580 - 0x0000000000000640 is .rela.dyn
	0x0000000000000640 - 0x0000000000000670 is .rela.plt
	0x0000000000001000 - 0x0000000000001017 is .init
	0x0000000000001020 - 0x0000000000001050 is .plt
	0x0000000000001050 - 0x0000000000001058 is .plt.got
	0x0000000000001060 - 0x00000000000011d0 is .text
	0x00000000000011d0 - 0x00000000000011d9 is .fini
	0x0000000000002000 - 0x0000000000002018 is .rodata
	0x0000000000002018 - 0x000000000000204c is .eh_frame_hdr
	0x0000000000002050 - 0x000000000000211c is .eh_frame
	0x0000000000003dd0 - 0x0000000000003dd8 is .init_array
	0x0000000000003dd8 - 0x0000000000003de0 is .fini_array
	0x0000000000003de0 - 0x0000000000003fc0 is .dynamic
	0x0000000000003fc0 - 0x0000000000003fe8 is .got
	0x0000000000003fe8 - 0x0000000000004010 is .got.plt
	0x0000000000004010 - 0x0000000000004020 is .data
	0x0000000000004020 - 0x0000000000004028 is .bss
```



### registers

查看寄存器信息

```
(gdb) info registers 
rax            0x55555555516a      93824992235882
rbx            0x7fffffffe2c8      140737488347848
rcx            0x555555557dd8      93824992247256
rdx            0x7fffffffe2d8      140737488347864
rsi            0x7fffffffe2c8      140737488347848
rdi            0x1                 1
rbp            0x7fffffffe1b0      0x7fffffffe1b0
rsp            0x7fffffffe1a0      0x7fffffffe1a0
r8             0x0                 0
r9             0x7ffff7fcfb10      140737353939728
r10            0x7ffff7fcb858      140737353922648
r11            0x7ffff7fe1e30      140737354014256
r12            0x0                 0
r13            0x7fffffffe2d8      140737488347864
r14            0x555555557dd8      93824992247256
r15            0x7ffff7ffd000      140737354125312
rip            0x555555555179      0x555555555179 <main+15>
eflags         0x206               [ PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```



## disassemble

`disassemble`查看当前函数汇编代码

`disassemble [函数名]`查看指定函数汇编代码



## examine

使用`examine`命令（简写为`x`）来查看内存地址中的内容。`x`命令的语法如下¹：

```shell
x/nfu addr
```

其中：

- `n` 是一个正整数，表示显示的内存单元的个数，比如：20¹。
- `f` 表示显示方式，可取如下值¹：
    - `x` 按十六进制格式显示变量。
    - `d` 按十进制格式显示变量。
    - `u` 按十进制格式显示无符号整型。
    - `o` 按八进制格式显示变量。
    - `t` 按二进制格式显示变量。
    - `a` 按十六进制格式显示变量。
    - `i` 指令地址格式。
    - `c` 按字符格式显示变量。
    - `f` 按浮点数格式显示变量。
- `u` 表示一个地址单元的长度¹：
    - `b` 表示单字节。
    - `h` 表示双字节。
    - `w` 表示四字节。
    - `g` 表示八字节。
- `addr` 是要查看的内存地址¹。

例如，如果您想以十六进制格式查看从某个地址开始的20个双字节，您可以使用以下命令¹：

```shell
x /20xh addr
```