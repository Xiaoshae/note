



## checksec.sh

```
#解压
unzip checksec.sh-main.zip 

cd checksec.sh/

#创建软连接
ln -s checksec checkfile

#设置路径
```



## python

```
cd /usr/bin/
ln -s python3.9 python

python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --upgrade pip
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```



### pwntools

```
pip install pwntools

[root@localhost pwn]# checksec ret2shellcode
[*] '/root/pwn/ret2shellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments

[root@localhost pwn]# checkfile --file=ret2shellcode
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   79 Symbols	  No	0		3		ret2shellcode
```

