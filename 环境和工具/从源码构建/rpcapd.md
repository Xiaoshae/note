# 编译rpcapd

相关链接：

1. [rpcapd-linux](https://github.com/rpcapd-linux/rpcapd-linux)

2. [libpcap](https://github.com/the-tcpdump-group/libpcap)
3. [libpcap tag list](https://github.com/the-tcpdump-group/libpcap/tags)

rpcapd 是一个为 Windows 版本的 Wireshark 协议分析器提供远程流量捕获的守护进程。它随同 WinPcap 网络捕获库一起发布在 Windows 上，但在 Linux 中版本低于 1.9.0 的 libpcap 中缺失。

在 libpcap v1.9.0 及更高版本中，使用 `--enable-remote` 标志（ `./configure --enable-remote && make` ）编译时会生成 rpcapd 可执行文件。应使用**该文件（libpcap >= v1.9.0）**而不是**此分支（rpcapd-linux）**。



## 编译

安装依赖

```
apt-get update
apt install build-essential autoconf git flex bison
```



从 GitHub 仓库下获取 libpcap 的源码。

```
git clone https://github.com/the-tcpdump-group/libpcap.git
```



进入 **libpcap** 目录，并切换源码版本到最新的源码版本（tag）

```
git checkout libpcap-1.10.5
```

![image-20240923152830137](./images/rpcapd.assets/image-20240923152830137.png)





生成 **configure** 文件

```
autoreconf -i
```



**创建 build** 目录，并**切换到 build** 目录

```
mkdir build && cd build
```



使用 **configure** 生成 **Makefile** 文件，使用 **--enable-remote** 编译时会生成 rpcapd 可执行文件

```
../configure --enable-remote
```



（可选）使用 **CFLAGS="-static" LDFLAGS="-static"** 在编译时**使用静态链接**，方便将 rpcapd 移动到其他环境使用的时候**不需要安装库**。

注意：如果使用 **CFLAGS="-static" LDFLAGS="-static"** 则可能会编译失败，**但 rpcapd 可执行文件已经生成**，且可以正常运行。

```
../configure --enable-remote CFLAGS="-static" LDFLAGS="-static"
```



使用 make 编译生成可执行文件，指定 **-j** 参数 **make -j 2** 使用 2 线程编译，也可以 **make -j $(nproc)** 指定计算机所拥有的线程进行编译。**$(nproc)** 为计算机所有的**核心**数量。

```
make -j $(nproc)
```



编译成功后 **rpcapd** 文件会生成在 **rpcapd/rpcapd** 路径。

```
ls rpcapd/rpcapd
```



运行 **rpcapd** 已测试是否成功

```
./rpcapd 
Press CTRL + C to stop the server...
```

