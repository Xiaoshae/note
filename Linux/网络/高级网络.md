# Advanced Networking

## 基础知识

**注意**：这部分理论知识只需**简单了解即可**，暂时无需深入理解。



**Linux 网络栈** 是由多个功能模块组成的**分层、模块化系统**，并没有一个单一的“统一名称”来概括整个网络。

它是由**内核中的多个子系统协同工作实现的**，每个模块负责不同的功能，并通过清晰的接口进行交互，主要分为以下部分：

1. 网络设备驱动层

2. 链路层（L2）

3. 网络层（L3）
    - IP 协议栈
    - Netfilter 框架

4. 传输层（L4）
    - TCP/UDP 协议
    - Socket 接口
5. 虚拟化与隔离
    - 网络命名空间（netns）
    - eBPF 和 XDP



在 Linux 中，网络管理工具经历了从 **net-tools**（又称 **NET-3**）到 **iproute2** 的演进。早期的 **net-tools** 套件主要包含 `ifconfig` 和 `route` 等命令，而现代的 **iproute2** 套件则提供了更强大的工具，如 `ip`、`tc` 和 `iptables` 等。

**需要注意的是**，无论是 **net-tools** 还是 **iproute2**，它们都只是**用户空间工具**，用于配置和管理内核的网络功能，**本身并不实现网络协议栈或数据包处理**。Linux 网络的底层实现完全由**内核**完成，而 **iproute2** 通过 **netlink** 或其他系统调用（如 `ioctl`）与内核通信，动态调整路由、设备配置等网络参数。

iproute2 所做的网络配置都是临时的，**系统重启后所有配置都会丢失**。对于需要动态网络管理的场景（如桌面、移动设备），Linux 还提供了 **NetworkManager**。NetworkManager 是一个高级网络管理框架，它基于 iproute2 实现底层操作，但额外提供了 **自动连接管理**（如 Wi-Fi、VPN、DHCP）、**用户友好的配置接口**（GUI 和 `nmcli`）以及**持久化存储**，使得网络配置在重启后依然生效。目前，主流 Linux 发行版默认同时支持 iproute2 和 NetworkManager，前者适用于脚本和服务器管理，后者更适合桌面和动态网络环境。

**目前，主流 Linux 发行版默认使用 iproute2 进行网络管理，接下来的示例也将主要基于 iproute2 工具进行讲解。**



iproute2 通过 `ip` 命令提供模块化的功能，主要操作对象包括 **网络接口（物理 / 虚拟）**、**路由表**、**ARP 表**、**隧道**、**桥接**、**网络命名空间**等。

**Linux 网络命名空间（Network Namespace）** 的主要功能是 **隔离所有与网络相关的系统资源**，使得不同命名空间中的网络配置完全独立，就像运行在多个不同的网络环境中一样，在下面有示例演示**网络命名空间**。



**iproute2 所有操作对象（Objects）**

| **对象（Object）**              | **功能描述**                             | **常用命令示例**                                  |
| ------------------------------- | ---------------------------------------- | ------------------------------------------------- |
| `link`                          | 管理网络接口（设备）                     | `ip link show`, `ip link set eth0 up`             |
| `address` (或 `addr`)           | 管理IP地址                               | `ip addr add 192.168.1.1/24 dev eth0`             |
| `route`                         | 管理路由表                               | `ip route add default via 192.168.1.1`            |
| `rule`                          | 管理策略路由规则                         | `ip rule add from 192.168.1.10 lookup 100`        |
| `neighbor` (或 `neigh`)         | 管理ARP/NDISC缓存                        | `ip neigh show`                                   |
| `tunnel`                        | 配置IP隧道（GRE, IPIP等）                | `ip tunnel add gre0 mode gre remote 1.1.1.1`      |
| `maddress` (或 `maddr`)         | 管理组播地址                             | `ip maddr show`                                   |
| `monitor`                       | 实时监控网络事件                         | `ip monitor all`                                  |
| `xfrm`                          | 管理IPSec策略（加密/认证）               | `ip xfrm state show`                              |
| `token`                         | 管理IPv6地址生成令牌                     | `ip token set ::1 dev eth0`                       |
| `netns` (或 `netnsid`)          | 管理网络命名空间                         | `ip netns add ns1`                                |
| `l2tp`                          | 配置L2TPv3隧道                           | `ip l2tp add tunnel tunnel_id 1 peer_tunnel_id 1` |
| `macsec`                        | 配置MACsec加密链路                       | `ip macsec add dev eth0 sci 1`                    |
| `tcp_metrics` (或 `tcpmetrics`) | 管理TCP性能指标缓存                      | `ip tcp_metrics show`                             |
| `ila`                           | 管理Identifier-Locator Addressing (IPv6) | `ip ila add locator 1::1`                         |
| `vrf`                           | 管理虚拟路由转发实例                     | `ip vrf exec vrf1 ping 8.8.8.8`                   |
| `sr`                            | 管理Segment Routing (IPv6)               | `ip sr encap segs 2001:db8::2`                    |
| `nexthop`                       | 管理下一跳对象（内核4.19+）              | `ip nexthop add id 1 via 192.168.1.1`             |
| `mroute`                        | 管理组播路由（需内核支持）               | `ip mroute show`                                  |
| `bridge`                        | 管理桥接设备（部分功能）                 | `ip bridge addbr br0`                             |



## 网络命名空间

网络命名空间（Network Namespace）是 Linux 内核提供的一种 **网络隔离机制**，允许不同的进程组拥有独立的网络栈（包括网卡、IP 地址、路由表、防火墙规则等）。它是 Linux 容器（如 Docker、LXC）和虚拟化技术的基础之一。



**隔离的网络环境**：每个网络命名空间拥有自己的：

- 网络设备（物理/虚拟网卡）。
- IP 地址和子网配置。
- 路由表（`ip route`）。
- iptables/nftables 防火墙规则。
- 端口号空间（不同命名空间的进程可以绑定相同端口）。

**默认命名空间**：Linux 系统启动时创建的初始网络命名空间（`init_net`），所有未指定命名空间的进程默认使用它。

**轻量级**：相比虚拟机，网络命名空间是内核级隔离，性能损耗极低。



**创建网络命名空间**

```
ip netns add [name]
```

```
ip netns add n1
```



**在特定网络命名空间中执行命令**

```
ip netns exec [name] [command]
```

```
ip netns exec n1 ip link
```

输出结果：

```
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```

注：由于什么都没有创建，默认只存 lo（回环网卡）



**在特定网络命名空间中启动交互式 Shell**

```
ip netns exec n1 bash
```

表示 **在名为 `n1` 的隔离网络环境中启动一个交互式 Shell**，后续所有命令都在该网络命名空间内执行。

```
root@localhost:/# ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
root@localhost:/# exit
exit
```



**再创建一个名为 n2 的网络命名空间**

```
ip netns add n2
```



**查看 n2 网络命名空间状况**

```
root@localhost:/# ip netns exec n2 ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```



**虚拟网络对**

`veth`（Virtual Ethernet Pair）是 Linux 内核提供的一种 **成对出现的虚拟网络设备**，用于在不同网络命名空间（Network Namespace）或网络栈之间建立点对点连接。它类似于一根虚拟的以太网线，一端发送的数据会直接传输到另一端。



**创建虚拟网络对**

```
ip link add veth-n1 type veth peer name veth-n2
```

- **`veth-n1`** 和 **`veth-n2`**：这对虚拟网卡自定义的名称（可任意修改）。



**移动虚拟网卡**

```
ip link set veth-n1 netns n1
ip link set veth-n2 netns n2
```

- 将虚拟网卡 veth-n1 移动到 n1 网络命名空间
- 将虚拟网卡 veth-n2 移动到 n2 网络命名空间



**查看网络命名空间**

```
root@localhost:/# ip netns exec n1 ip a 
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
20: veth-n1@if19: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 16:1d:d3:67:46:e6 brd ff:ff:ff:ff:ff:ff link-netns n2
```

```
root@localhost:/# ip netns exec n2 ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
19: veth-n2@if20: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 3e:55:e6:7c:f3:6d brd ff:ff:ff:ff:ff:ff link-netns n1
```



**设置 IP 地址并启用网卡**

```
ip netns exec n1 ip address add 10.10.10.1/24 dev veth-n1
ip netns exec n1 ip link set veth-n1 up
```

```
ip netns exec n2 ip address add 10.10.10.2/24 dev veth-n2
ip netns exec n2 ip link set veth-n2 up
```



**查看网卡状态**

```
root@localhost:~# ip netns exec n1 ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
20: veth-n1@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 16:1d:d3:67:46:e6 brd ff:ff:ff:ff:ff:ff link-netns n2
    inet 10.10.10.1/24 scope global veth-n1
       valid_lft forever preferred_lft forever
    inet6 fe80::141d:d3ff:fe67:46e6/64 scope link 
       valid_lft forever preferred_lft forever
```

```
root@localhost:~# ip netns exec n2 ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
19: veth-n2@if20: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 3e:55:e6:7c:f3:6d brd ff:ff:ff:ff:ff:ff link-netns n1
    inet 10.10.10.2/24 scope global veth-n2
       valid_lft forever preferred_lft forever
    inet6 fe80::3c55:e6ff:fe7c:f36d/64 scope link 
       valid_lft forever preferred_lft forever
```



**在 n1 网络命名空间中 ping n2**

```
root@localhost:~# ip netns exec n1 ping 10.10.10.2 -c 4
PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
64 bytes from 10.10.10.2: icmp_seq=1 ttl=64 time=0.024 ms
64 bytes from 10.10.10.2: icmp_seq=2 ttl=64 time=0.041 ms
64 bytes from 10.10.10.2: icmp_seq=3 ttl=64 time=0.084 ms
64 bytes from 10.10.10.2: icmp_seq=4 ttl=64 time=0.058 ms

--- 10.10.10.2 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3096ms
rtt min/avg/max/mdev = 0.024/0.051/0.084/0.022 ms
```



## 虚拟网络接口

### lo（回环接口）

`lo`（Loopback Interface，回环接口）是 Linux 系统中一个**特殊的虚拟网络接口**，用于**本地进程间通信**（IPC），不依赖物理网络设备。它是操作系统网络栈的基础组件，默认在所有 Linux 系统中存在。

- **本地通信**：允许同一台机器上的应用程序通过 TCP/IP 协议互相通信（如 `127.0.0.1`）。
- **服务测试**：无需物理网络即可测试网络服务（如 Web 服务器监听 `127.0.0.1:8080`）。
- **内核和协议栈依赖**：许多系统服务（如 DNS 缓存、数据库）默认绑定到 `lo`。



`127.0.0.1` 只是 `127.0.0.0/8` 网段中最常用的一个地址，但**整个 127.0.0.0/8 网段（约 1600 万个 IP）均指向本地回环接口**，整个 `127.x.x.x` 都能 ping 通。

```
root@localhost:~# ping 127.0.0.1 -c 4
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.024 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.045 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.075 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.083 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3057ms
rtt min/avg/max/mdev = 0.024/0.056/0.083/0.023 ms
```

```
root@localhost:~# ping 127.124.231.89 -c 4
PING 127.124.231.89 (127.124.231.89) 56(84) bytes of data.
64 bytes from 127.124.231.89: icmp_seq=1 ttl=64 time=0.037 ms
64 bytes from 127.124.231.89: icmp_seq=2 ttl=64 time=0.091 ms
64 bytes from 127.124.231.89: icmp_seq=3 ttl=64 time=0.060 ms
64 bytes from 127.124.231.89: icmp_seq=4 ttl=64 time=0.044 ms

--- 127.124.231.89 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3058ms
rtt min/avg/max/mdev = 0.037/0.058/0.091/0.020 ms
```





### veth

`veth`（Virtual Ethernet Pair）是 Linux 内核提供的一种 **成对出现的虚拟网络设备**，用于在不同网络命名空间（Network Namespace）或网络栈之间建立点对点连接。它类似于一根虚拟的以太网线，一端发送的数据会直接传输到另一端。

**上面已经介绍过了，略**





### TUN/TAP

TUN/TAP 的核心作用是**”拦截“并重定向系统中的网络数据**。当进程（如浏览器）发起网络请求时，数据包会被路由到 TUN/TAP 虚拟设备（而非直接通过物理网卡）。这些数据随后**由用户态程序（如 VPN 客户端）接管处理**，经过加密或修改等操作后，最终 **VPN 客户端**通过物理网卡传输到目标服务器。

**这里做实验很蛮烦，略**



### VLAN

**VLAN（Virtual Local Area Network）** 是一种通过逻辑方式划分物理网络的技术，它用于将单一物理网络划分为多个虚拟网络，提高安全性、减少广播流量，并简化网络管理（例如隔离部门流量或不同服务）。



创建两个命名空间 **ns1** 和 **ns2**，并通过 **veth pair** 将它们连接起来，模拟两台电脑通过网线直连的场景。

```bash
# 创建命名空间
ip netns add ns1
ip netns add ns2

# 启用回环接口
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up

# 创建 veth pair 并移入命名空间
ip link add veth-ns1 type veth peer name veth-ns2

ip link set veth-ns1 netns ns1
ip link set veth-ns2 netns ns2
```



在 Linux 命名空间中配置网卡 IP 地址后，两个命名空间就可以互相通信。

```
ip netns exec ns1 bash
ip address add 172.16.0.1/24 dev veth-ns1
ip link set veth-ns1 up 
```

```
ip netns exec ns2 bash
ip address add 172.16.0.2/24 dev veth-ns2
ip link set veth-ns2 up 
```





**普通接口**和 **VLAN 接口**的关键区别在于数据包的封装方式：

- **普通接口**：发送的数据包**不携带 VLAN 标签（802.1Q）**，直接以原始格式传输。
- **VLAN 接口**：发送的数据包会**嵌入 VLAN ID（1-4094）**，符合 **802.1Q 标准**，使得网络设备（如交换机）能识别并正确处理不同 VLAN 的流量。

下面是配置 VLAN 接口的方法：

```bash
ip netns exec ns1 bash
ip link add link veth-ns1 name veth-ns1.100 type vlan id 100
ip address add 10.10.10.1/24 dev veth-ns1.100
ip link set veth-ns1.100 up
```

```bash
ip netns exec ns2 bash
ip link add link veth-ns2 name veth-ns2.100 type vlan id 100
ip address add 10.10.10.2/24 dev veth-ns2.100
ip link set veth-ns2.100 up
```



**查看 ns1 命名空间中接口的情况：**

```bash
root@localhost:~# ip netns exec ns1 ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: veth-ns1.100@veth-ns1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether c6:fc:c9:90:6b:12 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.1/24 scope global veth-ns1.100
       valid_lft forever preferred_lft forever
    inet6 fe80::c4fc:c9ff:fe90:6b12/64 scope link 
       valid_lft forever preferred_lft forever
24: veth-ns1@if23: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether c6:fc:c9:90:6b:12 brd ff:ff:ff:ff:ff:ff link-netns ns2
    inet 172.16.0.1/24 scope global veth-ns1
       valid_lft forever preferred_lft forever
    inet6 fe80::c4fc:c9ff:fe90:6b12/64 scope link 
       valid_lft forever preferred_lft forever
```



**查看 ns2 命名空间中的接口情况：**

```bash
root@localhost:~# ip netns exec ns2 ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: veth-ns2.100@veth-ns2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether f6:b7:27:a0:7b:58 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.2/24 scope global veth-ns2.100
       valid_lft forever preferred_lft forever
    inet6 fe80::f4b7:27ff:fea0:7b58/64 scope link 
       valid_lft forever preferred_lft forever
23: veth-ns2@if24: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether f6:b7:27:a0:7b:58 brd ff:ff:ff:ff:ff:ff link-netns ns1
    inet 172.16.0.2/24 scope global veth-ns2
       valid_lft forever preferred_lft forever
    inet6 fe80::f4b7:27ff:fea0:7b58/64 scope link 
       valid_lft forever preferred_lft forever
```



**连通性测试：**

```bash
root@localhost:~# ip netns exec ns1 ping 172.16.0.2 -c 3
PING 172.16.0.2 (172.16.0.2) 56(84) bytes of data.
64 bytes from 172.16.0.2: icmp_seq=1 ttl=64 time=0.119 ms
64 bytes from 172.16.0.2: icmp_seq=2 ttl=64 time=0.129 ms
64 bytes from 172.16.0.2: icmp_seq=3 ttl=64 time=0.099 ms

--- 172.16.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2081ms
rtt min/avg/max/mdev = 0.099/0.115/0.129/0.012 ms
```

```bash
root@localhost:~# ip netns exec ns1 ping 10.10.10.2 -c 3
PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
64 bytes from 10.10.10.2: icmp_seq=1 ttl=64 time=0.297 ms
64 bytes from 10.10.10.2: icmp_seq=2 ttl=64 time=0.061 ms
64 bytes from 10.10.10.2: icmp_seq=3 ttl=64 time=0.114 ms

--- 10.10.10.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2078ms
rtt min/avg/max/mdev = 0.061/0.157/0.297/0.101 ms
```



### MACVLAN

MACVLAN 是 Linux 内核提供的一种高级网络虚拟化技术，允许在单个物理网络接口上创建多个虚拟接口（子接口），每个虚拟接口拥有独立的 MAC 地址，并可直接与外部网络通信。

- **独立 MAC 地址**：每个 MACVLAN 子接口有唯一的 MAC 地址，对外表现为独立的物理设备。
- **无桥接开销**：直接复用物理接口的带宽，无需通过软件桥接（如 `brctl`），性能更高。
- **模式灵活**：支持多种通信模式（如 `private`、`vepa`、`bridge`、`passthru` 等）。



**MACVLAN 的工作模式**

- **Bridge 模式**：子接口之间可以直接通信（类似交换机），子接口之间的通信 **直接由 Linux 内核处理**，**不会经过物理交换机**。
    - 路径：子接口A → 内核虚拟交换机 → 子接口B（全程在宿主机内部完成）。
- **VEPA 模式**：子接口之间的通信 **必须通过物理交换机**（即使在同一宿主机上）。
    - 路径：子接口A → 物理网卡 → 外部交换机 → 物理网卡 → 子接口B。
- **Private 模式**：完全隔离子接口，即使同一宿主机上的子接口也无法直接通信。
- **Passthru 模式**：将物理接口直接分配给一个 MACVLAN 实例，独占使用。
    - **父接口**无法再用于普通网络通信，**不能创建额外的 MACVLAN 子接口**。



**注意：MACVLAN 所有工作模式父接口无法与子接口通讯。**





创建三个命名空间 **ns1**、**ns2** 和 **ns3**，并将一块**物理网卡**（如 `ens41`）移动到 **ns1** 命名空间中。随后，在 **ns1** 中为该网卡**配置 IP 地址**，使其能够访问外部网络。

```bash
# 创建三个命名空间
ip netns add ns1
ip netns add ns2
ip netns add ns3

# 启动命名空间中的 lo 接口
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up
ip netns exec ns3 ip link set lo up

# 将物理网卡 ens41 移动到 ns1 命名空间
ip link set ens41 netns ns1

# 进入 ns1 命名空间并配置 ens41 网卡的 IP 和路由
ip netns exec ns1 bash
ip address add 10.40.1.246/24 dev ens41
ip link set ens41 up
ip route add default via 10.40.1.254 dev ens41
```



测试 **ns1** 网络命名空间中 **ens41** 网卡与外部网络的连通性

```bash
root@localhost:~# ping 8.8.8.8 -c 2 
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=53 time=22.3 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=53 time=22.1 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 22.138/22.198/22.258/0.060 ms
```





#### Bridge

在 **ns1** 命名空间中，基于 **ens41** 创建 **2 个 macvlan 子接口**，模式设为 **bridge**，并将这两个子接口分别移动到 **ns2** 和 **ns3** 命名空间。

```bash
# 在 ns1 中创建两个 macvlan 子接口（ens41m1 和 ens41m2）
ip link add ens41m1 link ens41 type macvlan mode bridge
ip link add ens41m2 link ens41 type macvlan mode bridge

# 将子接口分别移动到 ns2 和 ns3
ip link set ens41m1 netns ns2
ip link set ens41m2 netns ns3

# 配置 ens41m1 接口的 IP 和路由
ip netns exec ns1 bash
ip address add 10.40.1.247/24 dev ens41m1
ip link set ens41m1 up
ip route add default via 10.40.1.254 dev ens41m1

# 配置 ens41m2 接口的 IP 和路由
ip netns exec ns3 bash
ip address add 10.40.1.248/24 dev ens41m2
ip link set ens41m2 up
ip route add default via 10.40.1.254 dev ens41m2
```



测试 **ns2** 网络命名空间中 **ens41m1** 网卡与外部网络的连通性

```bash
root@localhost:~# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=53 time=31.5 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=53 time=31.5 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 31.464/31.481/31.498/0.017 ms
```



测试 **ns3** 网络命名空间中 **ens41m2** 网卡与外部网络的连通性

```bash
root@localhost:~# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=53 time=31.5 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=53 time=31.5 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 31.464/31.481/31.498/0.017 ms
```



测试 **ens41m1**（macvlan 子接口）与 **ens41m2**（macvlan 子接口）的连通性 **ens41m1 ping ens41m2**。

```bash
root@localhost:~# ping 10.40.1.248 -c 2 
PING 10.40.1.248 (10.40.1.248) 56(84) bytes of data.
64 bytes from 10.40.1.248: icmp_seq=1 ttl=64 time=0.032 ms
64 bytes from 10.40.1.248: icmp_seq=2 ttl=64 time=0.036 ms

--- 10.40.1.248 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1064ms
rtt min/avg/max/mdev = 0.032/0.034/0.036/0.002 ms
```



测试 **ens41m2**（macvlan 子接口）与 **ens41**（父接口，物理网卡）的连通性，**无法连通（正常情况）**。

```bash
root@localhost:~# ping 10.40.1.246 
PING 10.40.1.246 (10.40.1.246) 56(84) bytes of data.
^C
--- 10.40.1.246 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1001ms
```



#### VEPA

在 **ns1** 命名空间中，基于 **ens41** 创建 **2 个 macvlan 子接口**，模式设为 **VEPA**，并将这两个子接口分别移动到 **ns2** 和 **ns3** 命名空间。**命令**与创建 **bridge 模式** 时基本相同，仅需将 `mode bridge` 替换为 `mode vepa`。

```bash
# 在 ns1 中创建两个 macvlan 子接口（ens41m1 和 ens41m2）
ip link add ens41m1 link ens41 type macvlan mode vepa
ip link add ens41m2 link ens41 type macvlan mode vepa

# 将子接口分别移动到 ns2 和 ns3
ip link set ens41m1 netns ns2
ip link set ens41m2 netns ns3

# 配置 ens41m1 接口的 IP 和路由
ip netns exec ns2 bash
ip address add 10.40.1.247/24 dev ens41m1
ip link set ens41m1 up
ip route add default via 10.40.1.254 dev ens41m1

# 配置 ens41m2 接口的 IP 和路由
ip netns exec ns3 bash
ip address add 10.40.1.248/24 dev ens41m2
ip link set ens41m2 up
ip route add default via 10.40.1.254 dev ens41m2
```



测试 **ens41m1**（macvlan 子接口）与 **ens41m2**（macvlan 子接口）的连通性 **ens41m1 ping ens41m2**。

```bash
root@localhost:~# ping 10.40.1.248 -c 2
PING 10.40.1.248 (10.40.1.248) 56(84) bytes of data.
64 bytes from 10.40.1.248: icmp_seq=1 ttl=255 time=0.456 ms
64 bytes from 10.40.1.248: icmp_seq=2 ttl=255 time=0.543 ms

--- 10.40.1.248 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1034ms
rtt min/avg/max/mdev = 0.456/0.499/0.543/0.043 ms
```

注意：**观察子接口通讯的延迟**，在 **Bridge 模式** 下，子接口之间的通信直接由 **内核网络栈** 进行数据转发，因此 **延迟极低**。而在 **VEPA 模式** 下，子接口的数据必须经过 **外部交换机** 进行转发，相比 Bridge 模式，**延迟明显增加**，因为数据包需要经历物理链路的传输和交换机的处理。



#### Private

在 **ns1** 命名空间中，基于 **ens41** 创建 **2 个 macvlan 子接口**，模式设为 **Private**，并将这两个子接口分别移动到 **ns2** 和 **ns3** 命名空间。**命令**与创建 **bridge 模式** 时基本相同，仅需将 `mode bridge` 替换为 `mode private`。

```bash
# 在 ns1 中创建两个 macvlan 子接口（ens41m1 和 ens41m2）
ip link add ens41m1 link ens41 type macvlan mode private
ip link add ens41m2 link ens41 type macvlan mode private

# 将子接口分别移动到 ns2 和 ns3
ip link set ens41m1 netns ns2
ip link set ens41m2 netns ns3

# 配置 ens41m1 接口的 IP 和路由
ip netns exec ns2 bash
ip address add 10.40.1.247/24 dev ens41m1
ip link set ens41m1 up
ip route add default via 10.40.1.254 dev ens41m1

# 配置 ens41m2 接口的 IP 和路由
ip netns exec ns3 bash
ip address add 10.40.1.248/24 dev ens41m2
ip link set ens41m2 up
ip route add default via 10.40.1.254 dev ens41m2
```



测试 **ens41m1**（macvlan 子接口）与 **ens41m2**（macvlan 子接口）的连通性 **ens41m1 ping ens41m2**。

```
root@localhost:~# ping 10.40.1.248
PING 10.40.1.248 (10.40.1.248) 56(84) bytes of data.
From 10.40.1.247 icmp_seq=1 Destination Host Unreachable
From 10.40.1.247 icmp_seq=5 Destination Host Unreachable
From 10.40.1.247 icmp_seq=6 Destination Host Unreachable
^C
--- 10.40.1.248 ping statistics ---
7 packets transmitted, 0 received, +3 errors, 100% packet loss, time 6169ms
pipe 4
```



#### Passthru

**Passthru 模式**通常用于让单个虚拟机或容器独占物理网卡，同时避免其直接控制物理接口。具体实现方式是：基于父接口（物理网卡）创建一个 **Passthru 模式的 macvlan 子接口**，并将该子接口分配给容器或虚拟机使用。

对于容器场景，**子接口会被移动到对应容器的网络命名空间（Network Namespace）中**，使其完全独立于宿主机网络栈。这种方案既能**保证网络性能**（类似直通），又能**隔离对物理网口的直接操作**，兼顾安全性与资源独占性。



下面是一个完整的示例，演示如何基于 `ens41` 物理网卡创建 **Passthru 模式的 macvlan 子接口**，并验证其独占性（无法创建第二个子接口，且父接口无法分配 IP），最后将子接口移动到 `ns2` 网络命名空间并配置 IP 使其正常上网。

```bash
# 启用 ns1 中的 ens41 接口
ip link set ens41 up

# 在 ns1 中创建 Passthru 模式的 macvlan 子接口
ip link add macvlan1 link ens41 type macvlan mode passthru

# 尝试创建第二个 macvlan 子接口（会失败）
root@localhost:~# ip link add macvlan2 link ens41 type macvlan mode passthru
RTNETLINK answers: Invalid argument   # RTNETLINK 回复：无效参数

# 将子接口 macvlan1 移动到 ns2
ip link set macvlan1 netns ns2
```



**在 ns2 中启用子接口并分配 IP**

```bash
ip netns exec ns2 bash
ip netns exec ns2 ip addr add 10.40.1.247/24 dev macvlan1
ip netns exec ns2 ip link set macvlan1 up
ip route add default via 10.40.1.254 dev macvlan1
```



在创建 macvlan 子接口时，**父接口的状态直接影响子接口的通信能力**。

**父接口状态的关键作用**

- 如果父接口处于 `down` 状态，子接口即使分配了 IP 并设置为 `up`，**也无法通过父接口发送数据包**。此时，子接口只能 `ping` 通自己（实际上是 `lo` 回环接口在响应）。
- 当父接口恢复 `up` 状态后，子接口才能正常与外网通信。

**父接口的 IP 配置限制**

- 创建 macvlan 子接口后，**父接口仍然可以配置 IP 地址**，但**父接口本身无法通过该 IP 与外部通信**，只能 `ping` 通自己（同样依赖 `lo` 接口）。
- 这是因为 macvlan 子接口会接管父接口的数据包处理。



**测试子接口 macvlan1 与外部的通讯**

```bash
root@localhost:~# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=53 time=31.4 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=53 time=31.7 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 31.449/31.565/31.681/0.116 ms
```



测试**父接口 ens41** 与外部的通讯

```bash
root@localhost:~# ping 10.40.1.254 -c 2
PING 10.40.1.254 (10.40.1.254) 56(84) bytes of data.

--- 10.40.1.254 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1043ms
```



### IPVLAN

IPvLAN 是 Linux 内核提供的一种高级网络虚拟化技术，允许在**单个物理网络接口上创建多个虚拟网络接口**，所有 **IPvLAN 子接口共享父接口的 MAC 地址**，通过不同的 IP 地址区分流量（与 Macvlan 不同，后者为每个子接口分配独立 MAC 地址）。



**IPvLAN 的工作模式**

- **L2：二层交换式处理**
- **L3：三层路由式处理**
- **L3S：三层路由式处理，此模式下 iptables（连接跟踪）正常工作，因此称为 L3 对称模式（L3s）。**





**实验基础配置**，创建三个命名空间 **ns1**、**ns2** 和 **ns3**，并将一块**物理网卡**（如 `ens41`）移动到 **ns1** 命名空间中。随后，在 **ns1** 中为该网卡**配置 IP 地址**，使其能够访问外部网络。

```bash
# 创建三个命名空间
ip netns add ns1
ip netns add ns2
ip netns add ns3

# 启动命名空间中的 lo 接口
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up
ip netns exec ns3 ip link set lo up

# 将物理网卡 ens41 移动到 ns1 命名空间
ip link set ens41 netns ns1

# 进入 ns1 命名空间并配置 ens41 网卡的 IP 和路由
ip netns exec ns1 bash
ip address add 192.168.7.220/24 dev ens41
ip link set ens41 up
ip route add default via 192.168.7.89 dev ens41
```



**模式标志**

- **bridge**：**默认选项**，除了通过父接口通信外，子接口间也可以互相通信。
- **vepa**：子接口间可以互相通信，**必须经过外部网络设备**。
- **private**：子接口间不可互相通信。



#### L2

在 IPvlan L2 模式下，**父接口与外部网络的通信行为与普通接口无异**，而子接口之间的通信通过 IPvlan 虚拟二层链路直接完成，**无需经过父接口**。当子接口访问外部网络时，二层数据包会直接从父接口转发出去，**父接口本身不会处理这些数据包**。

**需要注意的是**，如果子接口尝试访问父接口，其 ARP 请求会直接从父接口发出，但**父接口不会响应**，因此子接口默认无法直接与父接口通信。若需要实现子接口与父接口的通信，**必须依赖外部交换机的 VEPA（Virtual Ethernet Port Aggregator）反射功能**，否则无法完成直接通信。

子接口的协议栈会直接处理**二层封装/解封装**，不依赖父接口的IP层路由。子接口生成IP包后，**自行完成二层封装**，封装后的**完整以太网帧**直接交给父接口发送，**不经过父接口的路由表**。

父接口收到以太网帧后，根据目标MAC地址匹配到子接口。子接口**直接解析二层帧**，提取IP包交给自己的协议栈处理。

```bash
# 在 ns1 中创建两个 ipvlan 子接口（ipvlan1 和 ipvlan1）
ip link add ipvlan1 link ens41 type ipvlan mode l2
ip link add ipvlan2 link ens41 type ipvlan mode l2

# 将两个接口分别移动到 ns2 和 ns3
ip link set ipvlan1 netns ns2
ip link set ipvlan2 netns ns3

# 配置 ns2 中 ipvlan1 接口的 ip 和路由
ip netns exec ns2 bash
ip address add 192.168.7.230/24 dev ipvlan1
ip link set ipvlan1 up
ip route add default via 192.168.7.89

# 配置 ns3 中 ipvlan2 接口的 ip 和路由
ip netns exec ns3 bash
ip address add 192.168.7.240/24 dev ipvlan2
ip link set ipvlan2 up
ip route add default via 192.168.7.89
```



测试 **ns2** 网络命名空间中 **ipvlan1** 网卡与外部网络的连通性

```bash
root@localhost:/opt# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=49 time=112 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=49 time=134 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 111.699/122.746/133.793/11.047 ms
```



测试 **ns3** 网络命名空间中 **ipvlan2** 网卡与外部网络的连通性

```bash
root@localhost:~# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=49 time=257 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=49 time=279 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 257.038/268.073/279.109/11.035 ms
```



测试 **ipvlan1**（ IPVLAN 子接口）与 **ipvlan1**（ IPVLAN子接口）的连通性 **ipvlan1 ping ipvlan2**。

```bash
root@localhost:~# ping 192.168.7.240 -c 2
PING 192.168.7.240 (192.168.7.240) 56(84) bytes of data.
64 bytes from 192.168.7.240: icmp_seq=1 ttl=64 time=0.062 ms
64 bytes from 192.168.7.240: icmp_seq=2 ttl=64 time=0.103 ms

--- 192.168.7.240 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1037ms
rtt min/avg/max/mdev = 0.062/0.082/0.103/0.020 ms
```



测试 **ipvlan1**（IPVLAN 子接口）与 **ens41**（父接口，物理网卡）的连通性，**无法连通（正常情况）**。

```bash
root@localhost:~# ping 192.168.7.220 -c 2
PING 192.168.7.220 (192.168.7.220) 56(84) bytes of data.
From 192.168.7.230 icmp_seq=1 Destination Host Unreachable
From 192.168.7.230 icmp_seq=2 Destination Host Unreachable

--- 192.168.7.220 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1003ms
pipe 2
```



测试 **ipvlan1**（IPVLAN 子接口）与 **ens41**（父接口，物理网卡）的连通性，**交换器开启 vepa 反射**。

```
...
```



#### L3

L3 模式下子接口**仅完成IP层的封装/解封装**，**二层封装由父接口完成**。

子接口生成IP包后，**仅处理到IP层**（不填MAC地址）。将**纯IP包**交给父接口的协议栈，主设备负责：查询路由表确定下一跳、通过ARP获取下一跳MAC地址、完成二层封装后从主设备发出。

子接口收到以太网帧后，剥离二层头，将IP包交给子接口处理。子接口**只看到IP层数据**，无法直接获取原始MAC信息。

```bash
# 在 ns1 中创建两个 ipvlan 子接口（ipvlan1 和 ipvlan1）
ip netns exec ns1 bash
ip link add ipvlan1 link ens41 type ipvlan mode l3
ip link add ipvlan2 link ens41 type ipvlan mode l3

# 将两个接口分别移动到 ns2 和 ns3
ip link set ipvlan1 netns ns2
ip link set ipvlan2 netns ns3

# 配置 ns2 中 ipvlan1 接口的 ip 和路由
ip netns exec ns2 bash
ip address add 192.168.151.10/24 dev ipvlan1
ip link set ipvlan1 up
ip route add default via 192.168.151.254 # 虚拟网关（见下文解释）

# 配置 ns3 中 ipvlan2 接口的 ip 和路由
ip netns exec ns3 bash
ip address add 192.168.152.10/24 dev ipvlan2
ip link set ipvlan2 up
ip route add default via 192.168.152.254 # 虚拟网关（见下文解释）
```

IPvlan L3 模式下，所有流量必须**经过父接口所在网络空间的路由表**。此处 `192.168.151.254` 是一个**虚拟网关地址**（无需真实存在），目的是让内核将包交给主机处理。



当 **ns3** 中的设备 **ping 10.40.1.1** 时，**ns3** 根据**路由表**选择**默认路由（via 192.168.152.254）**作为下一跳。由于采用 **IPvlan L3 模式**，数据包**不会真正发往该网关地址**，而是**跳过二层封装**，直接由**内核 IP 层**处理。内核将数据包交给**父接口**后，依据**父接口所在网络命名空间的路由表**重新进行**路由决策**，可能匹配**直连路由**或**默认路由**进行转发。

IPvlan L3（Layer 3）模式让容器直接参与 **三层（IP）路由**，而不是像传统 Docker 网络那样依赖 NAT 或桥接。

- **容器流量直接进入主机的物理网络**（不经过 NAT）。
- **外部路由器必须知道如何回程路由**（即如何把响应包送回容器）。

```
root@localhost:~# ping 10.40.1.1 -c 1
PING 10.40.1.1 (10.40.1.1) 56(84) bytes of data.
64 bytes from 10.40.1.1: icmp_seq=1 ttl=128 time=0.677 ms

--- 10.40.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.677/0.677/0.677/0.000 ms
```

![image-20250415192038132](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/image-20250415192038132.png)



### VXLAN

**VXLAN**是一种网络协议，能够在现有IP网络上传输以太网流量，同时支持海量租户隔离。借助 24 位的段标识符（即 VXLAN 网络标识符 VNI），VXLAN 最多可支持 2^24（16,777,216）个虚拟局域网。

VXLAN 将带有 VXLAN 头部的二层帧封装进 UDP-IP 数据包，其结构如下：

![VXLAN encapsulates Layer 2 frames with a VXLAN header into a UDP-IP packet](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/vxlan_01.png)



VXLAN 通常部署在数据中心的虚拟化主机上，这些主机可能分布在多个机架中。

![Typical VXLAN deployment](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/vxlan.png)



以下是使用 VXLAN 的简单示例：

```bash
# Server A eth0 ip 1.1.1.1
ip link add vx0 type vxlan id 100 local 1.1.1.1 remote 2.2.2.2 dev eth0 dstport 4789

# Server B eth0 ip 2.2.2.2
ip link add vx0 type vxlan id 100 local 2.2.2.2 remote 1.1.1.1 dev eth0 dstport 4789
```

```bash
# Server A eth0 ip 1.1.1.1
ip link add vx0 type vxlan id 100 local 1.1.1.1 dev eth0 dstport 4789

# Server B eth0 ip 2.2.2.2
ip link add vx0 type vxlan id 100 local 2.2.2.2 remote 1.1.1.1 dev eth0 dstport 4789
```

```bash
# Server A eth0 ip 1.1.1.1
ip link add vx0 type vxlan id 100 local 1.1.1.1 remote 2.2.2.2 dev eth0 dstport 4789

# Server B eth0 ip 2.2.2.2
ip link add vx0 type vxlan id 100 local 2.2.2.2 dev eth0 dstport 4789
```



以下是较为完整的 VXLAN 示例：

```bash
# 首先创建两个网络命名空间 ns1 和 ns2，用于模拟两台独立的 Linux 主机：
ip netns add ns1
ip netns add ns2

# 每个命名空间都需要启用本地回环接口 lo 以确保基础网络功能正常：
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up

# 在 ns1 中创建 veth 对，一端保留在 ns1，另一端移动到 ns2，模拟两台主机通过物理网卡直连：
ip netns exec ns1 bash
ip link add eth0 type veth peer name eth0 netns ns2

# 进入 ns1 配置 eth0 接口并设置 IP 地址：
ip address add 172.16.0.10/24 dev eth0
ip link set eth0 up

# 在 ns1 中创建 VXLAN 接口 vx0，指定本地和远程 IP，并启用接口：
ip link add vx0 type vxlan id 100 local 172.16.0.10 remote 172.16.0.20 dev eth0 dstport 4789
ip address add 172.20.0.10/24 dev vx0
ip link set vx0 up

# 进入 ns2 配置 eth0 接口并设置 IP 地址：
ip netns exec ns2 bash
ip address add 172.16.0.20/24 dev eth0
ip link set eth0 up

# 在 ns2 中创建 VXLAN 接口 vx0，指定本地和远程 IP，并启用接口：
ip link add vx0 type vxlan id 100 local 172.16.0.20 remote 172.16.0.10 dev eth0 dstport 4789
ip address add 172.20.0.20/24 dev vx0
ip link set vx0 up
```



在 **ns1** 中测试与 **ns2** 的 **eth0** 网卡（IP: `172.16.0.20`）的连通性：

```
root@localhost:~# ping 172.16.0.20 -c 2
PING 172.16.0.20 (172.16.0.20) 56(84) bytes of data.
64 bytes from 172.16.0.20: icmp_seq=1 ttl=64 time=0.048 ms
64 bytes from 172.16.0.20: icmp_seq=2 ttl=64 time=0.086 ms

--- 172.16.0.20 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1015ms
rtt min/avg/max/mdev = 0.048/0.067/0.086/0.019 ms
```



在 **ns1** 中测试与 **ns2** 的 **vx0** 网卡（IP: `172.20.0.20`）的连通性：

```
root@localhost:~# ping 172.20.0.20 -c 2
PING 172.20.0.20 (172.20.0.20) 56(84) bytes of data.
64 bytes from 172.20.0.20: icmp_seq=1 ttl=64 time=0.178 ms
64 bytes from 172.20.0.20: icmp_seq=2 ttl=64 time=0.193 ms

--- 172.20.0.20 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1039ms
rtt min/avg/max/mdev = 0.178/0.185/0.193/0.007 ms
```



## 网桥

Linux 网桥是一种内核模块，**其行为类似于网络交换机，在连接到它的接口之间转发数据包，网桥成员接口必须与网桥在同一命名空间**。它通常用于在路由器、网关上，或在主机上的虚拟机与网络命名空间之间转发数据包。

```bash
# 创建三个网络命名空间 bridge ns1 ns2
ip netns add bridge
ip netns add ns1
ip netns add ns2

# 开启三个网络命名空间的 lo 接口
ip netns exec bridge ip link set lo up
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up

# 在 bridge 中创建桥接设备，命名为 bridge
ip netns exec bridge bash
ip link add bridge type bridge

# 设置桥接设备的 IP 地址，并启用
ip address add 172.16.10.100/24 dev bridge
ip link set bridge up

# 在 bridge 中继续创建两对 veth
ip link add veth-1r type veth peer name veth-1d
ip link add veth-2r type veth peer name veth-2d

# 将 veth-1r 和 veth-2r 加入桥接设备
ip link set veth-1r master bridge
ip link set veth-2r master bridge

# 启用 veth-1r 和 veth-2r 接口
ip link set veth-1r up
ip link set veth-2r up

# 将 veth-1d 和 veth-2d 分别移动到 ns1 和 ns2
ip link set veth-1d netns ns1
ip link set veth-2d netns ns2

# 在 ns1 空间中配置 veth-1d 接口的 IP 并启用
ip netns exec ns1 bash
ip address add 172.16.10.10/24 dev veth-1d
ip link set veth-1d up

# 在 ns2 空间中配置 veth-2d 接口的 IP 并启用
ip netns exec ns2 bash
ip address add 172.16.10.20/24 dev veth-2d
ip link set veth-2d up
```



在 **ns2** 中的 **veth-2d** 接口（IP：`172.16.10.20`）测试与以下目标的连通性：

1. **ns1** 中的 **veth-1d** 接口（IP：`172.16.10.10`）；
2. **bridge** 命名空间中的 **bridge** 接口（IP：`172.16.10.100`）。

```bash
root@localhost:~# ping 172.16.10.10 -c 2
PING 172.16.10.10 (172.16.10.10) 56(84) bytes of data.
64 bytes from 172.16.10.10: icmp_seq=1 ttl=64 time=0.041 ms
64 bytes from 172.16.10.10: icmp_seq=2 ttl=64 time=0.096 ms

--- 172.16.10.10 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1051ms
rtt min/avg/max/mdev = 0.041/0.068/0.096/0.027 ms
```

```bash
root@localhost:~# ping 172.16.10.100 -c 2
PING 172.16.10.100 (172.16.10.100) 56(84) bytes of data.
64 bytes from 172.16.10.100: icmp_seq=1 ttl=64 time=0.036 ms
64 bytes from 172.16.10.100: icmp_seq=2 ttl=64 time=0.063 ms

--- 172.16.10.100 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1049ms
rtt min/avg/max/mdev = 0.036/0.049/0.063/0.013 ms
```



## Docker bridge

下面将基于 **Linux 底层网络知识**，逐步演示如何**“手搓”（手动搭建）**一个 **Docker 容器 Bridge 网络**。

```bash
# 创建三个网络命名空间：docker、nginx 和 gitlab。
# 其中，docker 命名空间模拟主网络环境，作为基础网络栈；而 
# nginx 和 gitlab 命名空间则模拟两个独立容器的网络环境，实现隔离。
ip netns add docker
ip netns add nginx
ip netns add gitlab

# 为 docker、nginx 和 gitlab 三个网络命名空间分别启动 lo 接口
ip netns exec docker ip link set lo up
ip netns exec nginx  ip link set lo up
ip netns exec gitlab ip link set lo up

# 首先 添加一张物理或虚拟网卡，确保该网卡能够访问外部网络。
# 接着，将这张网卡从 主网络命名空间 移动到 docker 网络命名空间，以便为容器环境提供外部网络连接能力。
ip link set ens41 netns docker

# 进入 docker 网络命名空间，为 ens41 网卡配置 IP 地址并设置路由。
ip netns exec docker bash
ip address add 192.168.54.230/24 dev ens41
ip link set ens41 up
ip route add default via 192.168.54.51 dev ens41

# 创建并配置桥接设备 docker0，设置 IP 地址并激活设备。
ip link add docker0 type bridge
ip address add 172.17.0.1/16 dev docker0
ip link set docker0 up

# 创建一个 veth 对，将其中一端接入 docker0 桥接设备，另一端移动到 nginx 的网络命名空间。
ip link add veth-nginx type veth peer name eth0
ip link set veth-nginx master docker0
ip link set veth-nginx up
ip link set eth0 netns nginx

# 创建一个 veth 对，将其中一端接入 docker0 桥接设备，另一端移动到 gitlab 的网络命名空间。
ip link add veth-gitlab type veth peer name eth0
ip link set veth-gitlab master docker0
ip link set veth-gitlab up
ip link set eth0 netns gitlab

# 进入 nginx 的网络命名空间，为 eth0 接口 配置 IP 地址 并设置 默认路由。
ip netns exec nginx bash
ip address add 172.17.10.10/16 dev eth0
ip link set eth0 up
ip route add default via 172.17.0.1 dev eth0

# 进入 gitlab 的网络命名空间，为 eth0 接口 配置 IP 地址 并设置 默认路由。
ip netns exec gitlab bash
ip address add 172.17.10.20/16 dev eth0
ip link set eth0 up
ip route add default via 172.17.0.1 dev eth0
```



查看 **docker** 网络命名空间中的接口状况

```bash
root@localhost:~# ip netns exec docker ip a 
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 16:04:30:73:11:eb brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::d815:ffff:feef:cdb5/64 scope link 
       valid_lft forever preferred_lft forever
4: veth-nginx@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default qlen 1000
    link/ether 1e:d6:88:3d:97:93 brd ff:ff:ff:ff:ff:ff link-netns nginx
    inet6 fe80::1cd6:88ff:fe3d:9793/64 scope link 
       valid_lft forever preferred_lft forever
6: veth-gitlab@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default qlen 1000
    link/ether 16:04:30:73:11:eb brd ff:ff:ff:ff:ff:ff link-netns gitlab
    inet6 fe80::1404:30ff:fe73:11eb/64 scope link 
       valid_lft forever preferred_lft forever
17: ens41: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:24:d9:ac brd ff:ff:ff:ff:ff:ff
    altname enp2s9
    inet 192.168.54.230/24 scope global ens41
       valid_lft forever preferred_lft forever
    inet6 2409:8950:eba:47:20c:29ff:fe24:d9ac/64 scope global dynamic mngtmpaddr 
       valid_lft 3306sec preferred_lft 3306sec
    inet6 fe80::20c:29ff:fe24:d9ac/64 scope link 
       valid_lft forever preferred_lft forever
```



查看 **nginx** 网络命名空间中的接口状况

```bash
root@localhost:~# ip netns exec nginx ip a 
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 32:0e:7c:ac:eb:09 brd ff:ff:ff:ff:ff:ff link-netns docker
    inet 172.17.10.10/16 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::300e:7cff:feac:eb09/64 scope link 
       valid_lft forever preferred_lft forever
```



查看 **gitlab** 网络命名空间中的接口状况

```bash
root@localhost:~# ip netns exec gitlab ip a 
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 9e:e4:5c:ed:77:4f brd ff:ff:ff:ff:ff:ff link-netns docker
    inet 172.17.10.20/16 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::9ce4:5cff:feed:774f/64 scope link 
       valid_lft forever preferred_lft forever
```



**验证网络连通性**：测试 **docker0 网桥** 与 **nginx 的 eth0**、**gitlab 的 eth0** 之间的通信是否正常。

```bash
root@localhost:/# ping 172.17.10.10 -c 2
PING 172.17.10.10 (172.17.10.10) 56(84) bytes of data.
64 bytes from 172.17.10.10: icmp_seq=1 ttl=64 time=0.049 ms
64 bytes from 172.17.10.10: icmp_seq=2 ttl=64 time=0.062 ms

--- 172.17.10.10 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1047ms
rtt min/avg/max/mdev = 0.049/0.055/0.062/0.006 ms
```

```bash
root@localhost:/# ping 172.17.10.20 -c 2
PING 172.17.10.20 (172.17.10.20) 56(84) bytes of data.
64 bytes from 172.17.10.20: icmp_seq=1 ttl=64 time=0.068 ms
64 bytes from 172.17.10.20: icmp_seq=2 ttl=64 time=0.083 ms

--- 172.17.10.20 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1061ms
rtt min/avg/max/mdev = 0.068/0.075/0.083/0.007 ms
```



**验证网络连通性**：测试 **nginx 的 eth0** 与 **docker0 网桥**、**gitlab 的 eth0** 之间的通信是否正常。

```bash
root@localhost:~# ping 172.17.0.1 -c 2
PING 172.17.0.1 (172.17.0.1) 56(84) bytes of data.
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.075 ms
64 bytes from 172.17.0.1: icmp_seq=2 ttl=64 time=0.052 ms

--- 172.17.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1059ms
rtt min/avg/max/mdev = 0.052/0.063/0.075/0.011 ms
```

```bash
root@localhost:~# ping 172.17.10.20 -c 2
PING 172.17.10.20 (172.17.10.20) 56(84) bytes of data.
64 bytes from 172.17.10.20: icmp_seq=1 ttl=64 time=0.030 ms
64 bytes from 172.17.10.20: icmp_seq=2 ttl=64 time=0.048 ms

--- 172.17.10.20 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1036ms
rtt min/avg/max/mdev = 0.030/0.039/0.048/0.009 ms
```



**验证网络连通性**：测试 **gitlab 的 eth0** 与 **docker0 网桥**、**nginx 的 eth0** 之间的通信是否正常。

```bash
root@localhost:/mnt# ping 172.17.0.1 -c 2
PING 172.17.0.1 (172.17.0.1) 56(84) bytes of data.
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.050 ms
64 bytes from 172.17.0.1: icmp_seq=2 ttl=64 time=0.053 ms

--- 172.17.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1023ms
rtt min/avg/max/mdev = 0.050/0.051/0.053/0.001 ms
```

```bash
root@localhost:/mnt# ping 172.17.10.10 -c 2
PING 172.17.10.10 (172.17.10.10) 56(84) bytes of data.
64 bytes from 172.17.10.10: icmp_seq=1 ttl=64 time=0.038 ms
64 bytes from 172.17.10.10: icmp_seq=2 ttl=64 time=0.085 ms

--- 172.17.10.10 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1030ms
rtt min/avg/max/mdev = 0.038/0.061/0.085/0.023 ms
```



**检查 Docker 网络命名空间**：查看 **iptables filter 表** 中 **FORWARD 链** 的默认规则配置。

```bash
root@localhost:/# iptables -t filter -L 
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
```

检查 **iptables FORWARD 链** 的默认策略（policy）**为 ACCEPT**，若不是，则使用以下命令进行配置调整。

```bash
iptables -P FORWARD ACCEPT
```



虽然流量可以正常转发，但**源 IP 仍为 172.17.x.x（Docker 内部网络）**，导致外部网络无法正确响应。此时需要配置 **NAT（地址转换）** 以修正源 IP。

```
root@localhost:~# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1034ms
```

![image-20250416082618202](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/image-20250416082618202.png)



**配置 NAT 规则**：为 **172.17.0.0/16 网段** 启用 NAT，确保 **Nginx 和 GitLab 容器** 的网络命名空间能够正常访问外部网络。

```
iptables -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
```



**网络连通性测试**：验证 **Nginx 网络命名空间** 与 **外部网络** 的通信是否正常。

```
root@localhost:~# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=48 time=122 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=48 time=142 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 121.506/131.977/142.448/10.471 ms
```

![image-20250416082809914](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/image-20250416082809914.png)



**网络连通性测试**：验证 **Gitlab 网络命名空间** 与 **外部网络** 的通信是否正常。

```
root@localhost:~# ping 8.8.8.8 -c 2
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=48 time=257 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=48 time=174 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 174.149/215.368/256.588/41.219 ms
```

![image-20250416082902737](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/image-20250416082902737.png)



**配置 DNAT 端口转发规则**

- 将 **8080 端口** 的流量转发至 **172.17.10.10（Nginx）** 的 **80 端口**
- 将 **9090 端口** 的流量转发至 **172.17.10.20（GitLab）** 的 **80 端口**

```
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 172.17.10.10:80
iptables -t nat -A PREROUTING -p tcp --dport 9090 -j DNAT --to-destination 172.17.10.20:80
```



在 **Nginx** 和 **GitLab** 的网络命名空间中启动 **80 端口** 的 Web 服务

```
root@localhost:/opt# mkdir nginx gitlab
root@localhost:/opt# touch nginx/nginx.file
root@localhost:/opt# touch gitlab/gitlab.file

root@localhost:/opt# tree
.
├── gitlab
│   └── gitlab.file
└── nginx
    └── nginx.file
```

```
root@localhost:~# ip netns exec nginx python3 -m http.server 80 --bind 0.0.0.0 --directory /opt/nginx
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
root@localhost:~# ip netns exec gitlab python3 -m http.server 80 --bind 0.0.0.0 --directory /opt/gitlab
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



从外部网络通过浏览器访问 **192.168.54.230:8080**（对应 Nginx）

![image-20250416084733925](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/image-20250416084733925.png)



从外部网络通过浏览器访问 **192.168.54.230:9090**（对应 GitLab）

![image-20250416084710975](./images/Linux%E9%AB%98%E7%BA%A7%E7%BD%91%E7%BB%9C.assets/image-20250416084710975.png)
