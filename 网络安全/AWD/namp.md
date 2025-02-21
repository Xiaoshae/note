# nmap

Nmap（Network Mapper）是一款开源**网络扫描工具**，主要用于探测网络中的活跃设备、检测开放端口及服务状态。它通过发送定制数据包并分析响应，实现四大核心功能：发现**网络存活主机**，识别**端口状态**（开放/过滤/关闭），获取运行中的**服务名称与版本信息**，推测目标**操作系统类型**。此外，可分析**防火墙规则**并**绘制网络拓扑**，广泛应用于网络安全审计、系统维护和故障排查领域。



## 扫描目标

Nmap 支持多种格式来指定被扫描的目标。

### 单目标

指定一个 IP 地址或域名

```
nmap 192.168.1.1
nmap scanme.nmap.org
```



### CIDR网段扫描

- 格式：`IP/位数`
- 例如：`192.168.1.0/24` 扫描256个IP（前24位固定）
- 所允许的**最小值是/1**， 这将会扫描半个互联网。**最大值是/32**，这将会扫描该主机或IP地址。

```
nmap 172.16.0.0/16
```



**八位字节地址范围**

- 格式：`192.168.1-10,15.0-255`
- 跳过特定地址：`192.168.0-255.1-254`（排除.0和.255广播地址）
- 支持多段组合：`10-20.0-255.100.1-200`



IPv6地址只能用规范的**IPv6地址**或**主机名**指定。 CIDR 和八位字节范围不支持IPv6，因为它们对于IPv6几乎没什么用。



### 多目标管理

Nmap命令行接受多个主机说明，它们不必是相同类型。

```
nmap example.com 10.0.0.0/8 192.168.1.1-50
```



**文件导入目标**

通过选项`-iL targets.txt` 从文件内导入目标，每行一个目标，支持所有格式。

```
nmap -iL targets.txt
```



文件 targets.txt 内容示例：

```
example.com
10.0.0.0/8
192.168.1.1-50
```



**随机目标扫描**

选项 `-iR <hostnum>` 让 nmap 随机生成 hostnum 个公网 IP 地址并进行扫描。

```
nmap -iR 100
```



### 排除目标

如果要排除一些主机目标，`--exclude < host1 [，host2] [，host3]，... >` 选项加上以逗号分隔的列表排除它们。

```
nmap 172.16.0.0/16 --exclude 172.16.10.0/24,172.16.20-30.0-255
```



### 文件排除列表

选项 `--excludefile <excludefile>` 排除文件中指定的主句目标。

```
nmap -iL targets.txt --excludefile exclude.txt
```



文件 targets.txt 内容示例

```
172.16.0.0/16
```



文件 exclude.txt 内容示例

```
172.16.10.0/24
172.16.20-30.0-255
```



### 示例

```
nmap scanme.nmap.org 192.168.0.0/16 \
	--exclude 192.168.1.1 \
	-iL targets.txt \
	--excludefile exclude.txt
```



## 主机发现

Nmap主机扫描旨从**一组 IP 范围中快速定位活动主机**，支持ICMP、TCP SYN/ACK、UDP、ARP等多种探测方式，可通过-P*选项组合协议（如-PE、-PA）。默认发送TCP ACK（非特权用户用SYN）和ICMP请求，局域网自动启用ARP扫描。安全审计建议组合探测技术穿透防火墙，提升识别精度。



### 列表扫描

选项 `-sL` 进行列表扫描，仅列出指定网络上的每台主机， 不发送任何报文到目标主机，验证目标IP范围正确性。默认情况下，会对这些主机进行反向域名解析。

```
nmap -sL 192.168.100.0/24 

Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-21 14:11 CST
Nmap scan report for 192.168.100.0
Nmap scan report for 192.168.100.1
Nmap scan report for 192.168.100.2
Nmap scan report for 192.168.100.3
Nmap scan report for 192.168.100.4
Nmap scan report for 192.168.100.5
Nmap scan report for 192.168.100.6
Nmap scan report for 192.168.100.7

Nmap scan report for 192.168.100.253
Nmap scan report for 192.168.100.254
Nmap scan report for 192.168.100.255
Nmap done: 256 IP addresses (0 hosts up) scanned in 0.38 seconds
```



### ping 扫描

选项 `-sP` 在默认情况下， Nmap默认行为会同时发送ICMP回声请求和TCP SYN报文至80端口（非特权用户通过connect() 发送SYN）。

该选项允许与除`-P0`之外的其他`-P*`类探测参数联合使用，例如结合`-PS`或`-PA`定制TCP探测策略。需特别注意：如果用户明确指定了其他探测类型或端口参数，此时Nmap仅执行用户定义的主机发现行为。

特权用户在局域网环境下的扫描，Nmap将自动采用ARP请求探测（-PR机制），但可通过`--send-ip`参数转为IP层探测。

```
nmap -sP  10.10.10.0/24 

Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-21 14:43 CST
Nmap scan report for 10.10.10.1
Host is up (0.00037s latency).
MAC Address: XX:XX:XX:XX:XX:XX (XXXX)
Nmap scan report for 10.10.10.101
Host is up (0.000067s latency).
MAC Address: XX:XX:XX:XX:XX:XX (XXXX)
Nmap scan report for 10.10.10.200
Host is up (0.000061s latency).
MAC Address: XX:XX:XX:XX:XX:XX (XXXX)
Nmap scan report for 10.10.10.100
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 0.76 seconds
```



### 无 ping

选项 `-P0 / -Pn` 跳过Nmap 主机发现阶段，就好像每个IP都是活动的。Nmap 对每一个指定的目标IP地址进行扫描。

```
root@xiaoshae:~# nmap -P0 -p- --min-rate 10000 -n 10.10.10.100 10.10.10.101
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-21 14:59 CST
Nmap scan report for 10.10.10.100
Host is up (0.0000080s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   filtered http
3306/tcp filtered mysql

Nmap scan report for 10.10.10.101
Host is up (0.0037s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
443/tcp  open  https
1024/tcp open  kdm
MAC Address: XX:XX:XX:XX:XX:XX (XXXX)

Nmap done: 2 IP addresses (2 hosts up) scanned in 7.90 seconds
```



### TCP SYN Ping

选项 `-PS [portlist]` 使 nmap 发送一个设置了SYN标志位的空TCP报文。 默认目的端口为80，通过 nmap.h 的 DEFAULT-TCP-PROBE-PORT 值设置默认端口。



**原始的TCP报文**

Nmap 发送 SYN 标志位告诉对方您正试图建立一个连接。 

- 如果**目标端口是关闭**的
    1. 一个RST (复位) 包会发回来。
- 如果**目标端口是开放**的
    1. 目标会进行TCP三步握手的第二步，回应 一个SYN/ACK TCP报文。
    2. 然后运行Nmap的机器则会扼杀这个正在建立的连接， 发送一个RST而非ACK报文。（否则，一个完全的连接将会建立）



**connect 方式**

如果 Nmap 是特权模式，则会为每个目标主机进行系统调用connect()，它也会发送一个SYN 报文来尝试建立连接。

如果connect()迅速返回成功或者一个 ECONNREFUSED 失败，下面的TCP堆栈一定已经收到了一个 SYN/ACK 或者 RST。

如果连接超时了，该主机就标志位为 down 掉了。



Nmap并不关心端口开放还是关闭。 **无论RST还是SYN/ACK响应都告诉Nmap该主机正在运行**。



### TCP ACK Ping

选项 -PA [portlist] 使 nmap 发送一个 TCP 设置 ACK 标志位的的数据包，默认端口 80。

ACK报文表示确认 TCP 连接的建立，因为远程主机并没有发出过连接请求到运行Nmap的机器，所以远程主机应该总是回应一个RST报文。

如果非特权用户尝试该功能， 或者指定的是IPv6目标，将使用 **connect 方式**。 这个方法并不完美，因为它实际上发送的是 SYN 报文，而不是 ACK 报文。



Nmap设计 SYN 和 ACK 两种 Ping 探测机制主要应对不同防火墙策略。

- 传统无状态防火墙常封锁入站SYN包（--syn规则），但已经建立连接的ACK包通过，此时ACK探测（-PA）更易穿透。
- 现代有状态防火墙会追踪连接状态，将无关联的ACK包视为异常流量拦截，此时SYN探测（-PS）成功率更高。

这一特性最开始只存在于高端防火墙，但是这些年类它越来越普遍了。 Linux Netfilter/iptables 通过 --state 选项支持这一特性，它可以追踪报文的连接状态。SYN 探测更有可能用于这样的系统，没头没脑的 ACK 报文通常会被识别，并丢弃。



由于网络环境存在多样性，最佳实践是同时启用 -PS 和 -PA 双探测模式，使扫描包既能绕过简单封SYN的规则，又能适应状态防火墙的过滤机制，最大化突破各类网络限制的可能性。

```
nmap -sP -PA -n 10.10.10.101-105

Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-21 15:31 CST
Nmap scan report for 10.10.10.101
Host is up (0.00020s latency).
MAC Address: XX:XX:XX:XX:XX:XX (XXXX)
Nmap done: 5 IP addresses (1 host up) scanned in 0.46 seconds
```



### UDP Ping

选项 `-PU [portlist]` 使 Nmap 默认发送一个空 UDP 数据包，`--data-length` 选项指定有效载荷的长度，默认端口是 31338。。



远程主机收到一个空 UDP 数据包：

- 如果目标机器的端口是关闭的，目标主机会回复 ICMP 端口无法到达的回应报文，意味着该机器正在运行。
- 如果到达一个开放的端口，大部分服务仅仅忽略这个空报文而不做任何回应。

只有收到 ICMP 端口无法到达的回应报文，Nmap 才认为该主机处于活动状态。



该扫描类型的主要优势是它可以穿越只过滤TCP的防火墙和过滤器。 例如。我某人有过一个 Linksys BEFW11S4 无线宽带路由器。默认情况下，该设备对外的网卡过滤所有 TCP 端口，但 UDP 探测仍然会引发一个端口不可到达的消息，从而暴露了它自己。



### ICMP Ping Types

ICMP 不仅仅只有 ICMP TYPE 8 (回声请求)，ICMP 标准还规范了**时间戳请求**，、**地址掩码请求**。 当管理员特别封锁了回声请求报文，而忘了其它 ICMP 查询可能用于相同目的时，这两个查询可能很有价值。

选项 `-PE` `-PP` `-PM` 分别用于发起**回声请求、时间戳请求、地址掩码请求**。



### ARP Ping

最常见的 Nmap 使用场景之一是扫描一个以太局域网。在大部分局域网上，绝大部分 IP地址都是不使用的。 当 Nmap 试图发送一个原始 IP 报文如 ICMP 回声请求时，操作系统必须通过 ARP 请求获得目标 IP 的 MAC 地址，操作系统设计者认为不会在短时间内对没有运行的机器作几百万次的 ARP 请求，所以一般比较慢而且会有些问题。

当进行ARP扫描时，Nmap用它优化的算法管理ARP请求。当它收到响应时，就表明目标机器处于运行状态。这使得 ARP 扫描比基于IP的扫描更快更可靠。 



默认情况下，如果Nmap发现目标主机就在它所在的局域网上，它会进行 ARP 扫描。 即使指定了不同的 ping 类型(如 `-PI`或者 `-PS`) ， Nmap 也会对任何相同局域网上的目标机使用ARP。 如果您真的不想要 ARP 扫描，指定 `--send-ip`。



### 关闭反向域名解析

选项 `-n` 使 Nmap 永不对它发现的活动IP地址进行反向域名解析。DNS一般比较慢。



### 开启反向域名解析

选项 `-R` 使 Nmap 永远对目标IP地址作反向域名解析。 一般只有当发现机器正在运行时才进行这项操作。



### 使用系统域名解析器

选项：`--system-dns`

默认情况下，Nmap通过直接发送查询到您的主机上配置的域名服务器 来解析域名。为了提高性能，许多请求 (一般几十个 ) 并发执行。

如果您希望使用系统自带的解析器，就指定该选项 (通过getnameinfo()调用一次解析一个IP)。



## 端口扫描





## 服务和版本探测



## 操作系统探测



