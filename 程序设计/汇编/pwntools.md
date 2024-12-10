# pwntools

Pwntools 是一个广泛使用的编写漏洞利用（exploit）的库。初次接触它可能会让人觉得有些棘手，但随着时间的推移，你会逐渐意识到它的强大之处。本文将尝试提供一个使用 Pwntools 编写漏洞利用的入门教程。



## 安装

### Python3

```bash
apt-get update
apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```



### Python2

```bash
apt-get update
apt-get install python python-pip python-dev git libssl-dev libffi-dev build-essential
python2 -m pip install --upgrade pip==20.3.4
python2 -m pip install --upgrade pwntools
```



## 连接到服务器或进程

在编写 CTF 挑战的漏洞利用时，我们通常需要连接到远程服务器，此时会给出 IP 地址和端口号。例如，如果给定的 IP 是 `10.10.95.109`，端口是 `9000`，我们可以这样连接：

```python
p = remote("<ip>", <port>)
p = remote("10.10.95.109", 9000)
```



如果我们只想连接到本地进程，可以这样做：

```python
p = process("./chal")
# 或者设置上下文 context.binary = "./chal" # 设置上下文后，自动告诉pwntools运行特定的二进制文件
# p = process()
# 或者我们可以创建一个ELF对象并将其附加到pwntools
context.binary = binary = ELF("./chal")
# p = process()
# p = binary.process()
```

设置`context.binary`或创建ELF对象将默认打印checksec结果（应用于此二进制文件的各种保护措施）。



示例：

```python
from pwn import *
context.binary = binary = ELF("./chal")
p = process()
```



## 接收输出

为了接收来自目标程序的输出，Pwntools 提供了几种方法：

- `p.recv()`：读取数据直到达到指定数量的字节。
- `p.recvline()`：读取一行数据。
- `p.recvall()`：读取所有数据直到 EOF。
- `p.recvuntil(delims)`：读取数据直到遇到指定的分隔符。



例如，添加 `print(p.recv())` 将显示从目标程序接收到的数据。请注意，Pwntools 接收的数据是以字节形式表示的，因此你可能需要处理字节与字符串之间的转换。



pwntools接收到的是字节码，以使用`p.recvuntil(b"briyani:\n")`。

如果使用`p.recvuntil(b"briyani:")`，我们可能还需要再调用一次`p.recv()`。



```python
recv(numb=4096, timeout=default) → bytes

recvline(keepends=True, timeout=default) → bytes

recvall(timeout=Timeout.forever) → bytes

recvuntil(delims, drop=False, timeout=default) → bytes
```



### 解包字节

使用`u64()`和`u32()`解包字节

- **`u64()`**：用于将8字节的小端字节序列解包为一个64位整数。
- **`u32()`**：用于将4字节的小端字节序列解包为一个32位整数。





## 发送有效载荷

发送有效载荷也有类似的方法，如 `send()`、`sendline()` 和 `sendafter()`。其中 `sendline()` 方法会在发送的数据末尾自动添加换行符 `\n`，模拟键盘上的回车键。

```python
p.send(payload) # 或 p.sendline(payload) # 或 p.sendafter(payload)
```



### 编写有效载荷

`p64()`函数可以用来将一个64位（8字节）的整数转换为小端格式的字节序列。对于给定的`main`函数地址`0x555555400992`，`p64()`会自动处理必要的字节序转换和零填充，确保输出为8字节长的字节串。

```python
# main函数地址
address = 0x555555400992

# 使用p64()函数将地址转换为小端格式的字节串
payload = p64(address)
```



使用`p32()`函数，它会将地址转换为32位（4字节）的小端格式。

```python
address = 0x804a030

payload = p32(address)
```



如果需要生成大端格式的有效载荷，可以在调用`p32()`或`p64()`时传递`endian='big'`参数。例如：

```python
payload = p64(address, endian='big')
```



## 调试

### 手动与进程交互

使用`p.interactive()`，我们可以像在典型终端中一样与进程交互。



### 日志

`context.log_level` 用来设置 `pwntools` 的日志级别。可以控制输出信息的详细程度，例如设置为 'debug' 可以看到更多的调试信息，而 'error' 则只显示错误信息。

**可用的日志级别：**

- `CRITICAL`
- `ERROR`
- `WARNING`
- `INFO`
- `DEBUG`
- `NOTSET`

```
context.log_level = "DEBUG"
```



### gdb

另一种调试漏洞利用程序的方式是使用gdb.attach()或gdb.debug()。这将在新终端中打开一个带有附加进程的gdb。

`gdb.attach` 函数允许你将 GDB（GNU Debugger）附加到一个正在运行的进程中。

**注意：gdb.attach 将 gdb 附加到进程后，并不会停止程序的继续执行。**

```
gdb.attach(p,gdbscript='''
    break * main + 190
    c ''')
```



`context.terminal` 用于指定 `pwntools` 使用的终端模拟器。这对于 `gdb.attach` 和其他需要打开新终端窗口的功能很重要。

```
context.terminal =  ['tmux', 'splitw', '-h']
```