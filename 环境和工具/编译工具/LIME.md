# LIME

LiME（Linux Memory Extractor）是一个可加载的内核模块（LKM），它允许从Linux和基于Linux的设备（如Android设备）获取易失性内存。

LiME的工作原理是，它在内核空间创建一个新的设备文件，然后将物理内存的内容复制到这个设备文件中。这样，用户空间的程序就可以从这个设备文件中读取内存的内容。



LiME和insmod的关系在于，LiME是一个内核模块，而insmod是用来加载内核模块的命令。所以，可以使用insmod命令来加载LiME模块。



## 准备编译环境

```
dnf -y groupinstall "开发工具"
dnf -y groupinstall "传统 UNIX 兼容性"

dnf -y install  kernel  #安装内核后需要重启
```



## 拉取lime源码

```
[root@localhost soft]# git clone https://github.com/504ensicsLabs/LiME.git
正克隆到 'LiME'...
remote: Enumerating objects: 370, done.
remote: Counting objects: 100% (21/21), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 370 (delta 10), reused 12 (delta 4), pack-reused 349
接收对象中: 100% (370/370), 1.61 MiB | 753.00 KiB/s, 完成.
处理 delta 中: 100% (199/199), 完成.
```



## 尝试第一次编译安装

```
[root@localhost soft]# cd LiME/src
[root@localhost src]# make
make -C /lib/modules/4.18.0-348.el8.x86_64/build M="/opt/soft/LiME/src" modules
make[1]: *** /lib/modules/4.18.0-348.el8.x86_64/build: 没有那个文件或目录。 停止。
make: *** [Makefile:35：default] 错误 2
```





缺少kernel-core和kernel-modules，安装后还是不行，这是因为linux kernel需要重启后才能重新加载，先要重启操作系统才能继续安装

注：内核热更新的操作这里不介绍

```
[root@localhost src]# dnf -y install kernel-modules
[root@localhost src]# make
make -C /lib/modules/4.18.0-348.el8.x86_64/build M="/opt/soft/LiME/src" modules
make[1]: *** /lib/modules/4.18.0-348.el8.x86_64/build: 没有那个文件或目录。 停止。
make: *** [Makefile:35：default] 错误 2
```



重启后再次进入/LiME/src目录使用make进行编译

其中lime-4.18.0-348.7.1.el8_5.x86_64.ko就是我们需要的内核

我们将其复制到一个新的文件夹中，准备将内存转储

```
[root@localhost src]# make
make -C /lib/modules/4.18.0-348.7.1.el8_5.x86_64/build M="/opt/soft/LiME/src" modules
make[1]: 进入目录“/usr/src/kernels/4.18.0-348.7.1.el8_5.x86_64”
  CC [M]  /opt/soft/LiME/src/tcp.o
/opt/soft/LiME/src/tcp.c: 在函数‘setup_tcp’中:
/opt/soft/LiME/src/tcp.c:75:5: 警告：ISO C90 不允许混合使用声明和代码 [-Wdeclaration-after-statement]
     int opt = 1;
     ^~~
  CC [M]  /opt/soft/LiME/src/disk.o
  CC [M]  /opt/soft/LiME/src/main.o
  CC [M]  /opt/soft/LiME/src/hash.o
  CC [M]  /opt/soft/LiME/src/deflate.o
  LD [M]  /opt/soft/LiME/src/lime.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /opt/soft/LiME/src/lime.mod.o
  LD [M]  /opt/soft/LiME/src/lime.ko
make[1]: 离开目录“/usr/src/kernels/4.18.0-348.7.1.el8_5.x86_64”
strip --strip-unneeded lime.ko
mv lime.ko lime-4.18.0-348.7.1.el8_5.x86_64.ko


[root@localhost src]# ls
deflate.c  disk.c  hash.c  lime-4.18.0-348.7.1.el8_5.x86_64.ko  lime.mod.c  lime.o  main.o    Makefile.sample  Module.symvers  tcp.o
deflate.o  disk.o  hash.o  lime.h                               lime.mod.o  main.c  Makefile  modules.order    tcp.c

[root@localhost src]# mkdir /root/mem/
[root@localhost src]# cp -p lime-4.18.0-348.7.1.el8_5.x86_64.ko /root/mem/
```



# insmod加载到内核



现在已经编译号了lime模块，可以使用insmod命令将模块加载到内核中运行，制作进行内存转储

lime-xxxxx.ko是需要加载到内核中运行的模块，"xxxxx"字符串是传递给lime模块的参数

```
[root@localhost mem]# insmod lime-4.18.0-348.7.1.el8_5.x86_64.ko "path=/root/mem/linux.mem format=raw"

[root@localhost mem]# ls
lime-4.18.0-348.7.1.el8_5.x86_64.ko  linux.mem

[root@localhost mem]# rmmod lime #读取完毕后取消加载lime模块
```



lime参数详解

```
insmod ./lime.ko "path=<outfile | tcp:<port>> format=<raw|padded|lime> [digest=<digest>] [dio=<0|1>]"
```

path：这是一个必需的参数，它指定了在本地系统上写入的文件名或要通信的网络端口。

```
#将lime模块加载到内核中，lime模块会持续监听tcp的4444端口
insmod lime-4.18.0-348.7.1.el8_5.x86_64.ko "path=tcp:4444 format=raw"

#另外一台服务器使用netcat工具连接到加载lime模块主机的4444端口，就可以从中读取数据了
nc ip 4444 > linux-nc.mem

[root@localhost mem]# rmmod lime #读取完毕后取消加载lime模块
```



format：这也是一个必需的参数，它指定了内存获取的格式。可选的值包括raw、padded和lime。

- raw 格式：这种格式将所有系统 RAM 区域连接在一起。但是需要注意的是，原始内存的位置信息可能会丢失。
- padded 格式：这种格式会用 0 填充所有非系统 RAM 区域。
- lime 格式：这种格式会在每个范围前加上固定大小的头部，包含地址空间信息。

digest：这是一个可选的参数，它可以用来对RAM进行哈希，并提供一个包含总和的.digest文件。

dio：这也是一个可选的参数，它可以尝试启用Direct IO。

启用direct IO: Direct IO，也称为直接I/O或无缓冲I/O，是一种绕过操作系统缓存直接从磁盘读写数据的技术23。当你启用Direct IO时，数据不会经过操作系统的缓存，而是直接从磁盘读取或写入到磁盘



参考视频：https://www.youtube.com/watch?v=o4JMVh2xVkw