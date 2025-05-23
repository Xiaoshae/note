# VXLAN

VXLAN（Virtual Extensible LAN）是一种网络虚拟化技术，旨在通过在三层 IP 网络上创建虚拟二层网络，解决传统 VLAN 的可扩展性限制。VLAN 使用 12 位标识符，仅支持 4096 个网络，而 VXLAN 使用 24 位的 VXLAN 网络标识符（VNI），支持多达 16777216 个虚拟网络。VXLAN 通过将以太网帧封装在 UDP 数据报中实现这一点，基于 IETF RFC 7348 标准，使用默认 UDP 端口 4789。



创建 VXLAN 接口示例，此命令创建一个名为 vxlan0 的 VXLAN 接口：

```
ip link add vxlan0 type vxlan id 42 group 239.1.1.1 dev eth1 dstport 4789
```

- **id 42**: VNI，标识虚拟网络
- **group**: 多播组地址，用于 BUM 流量
- **dev eth1**: 绑定的物理设备
- **dstport**: 目的 UDP 端口，默认为 4789



VXLAN 数据包通过 MAC-in-UDP 封装方案，将原始二层帧封装在三层 UDP 数据包中。数据包结构如下：

```
+0--------------7---------------15--------------23--------------31 -------------------------------
|           Source Port         |       Dest Port = VXLAN Port  |                 |
+---------------------------------------------------------------+             UDP Header
|           UDP Length          |        UDP Checksum           |                 |
+---------------------------------------------------------------+  -------------------------------
|  VXLAN Flags  |            Reserved_1                         |                 |
+---------------------------------------------------------------+            VXLAN Header
|                VXLAN Network Identifier       |   Reserved_2  |                 |
+---------------------------------------------------------------+  -------------------------------
```

![img](./images/linux%20vxlan.assets/download.png)



## 数据转发机制

当数据包通过 VXLAN 接口发送时，内核将原始以太网帧封装在 VXLAN 头中，添加 VNI，随后将其放入 UDP 数据报。数据转发机制的核心就是确定该数据包要发送到哪台目标机器上，**确定外层 IP 层数据包目标 IP 地址**。



**BUM 流量**

BUM 是 Broadcast（广播）、Unknown Unicast（未知单播）和 Multicast（多播）的缩写，指的是在二层网络中需要特殊处理的三类数据流量。

- **广播**：数据包的目标 MAC 地址为全 F（ff:ff:ff:ff:ff:ff），表示需要发送到网络中的所有设备。
- **未知单播：**数据包的目标 MAC 地址是单播地址，但发送设备（如 VXLAN 接口或网桥）的转发数据库（FDB）中没有该 MAC 地址对应的条目。
- **多播**：数据包的目标 MAC 地址是多播地址（以 01:00:5e 开头），用于发送到订阅了特定多播组的设备。



**FDB 表**

VXLAN 接口维护一个转发数据库（FDB），映射 MAC 地址到远程 VTEP IP 地址。

- 对于 BUM 流量通过 FDB 表中 00:00:00:00:00:00 条目对应的 VTEP IP 列表发送，执行头部复制（head-end replication）或多播分发。
- 对于非 BUM 流量（单播流量，不是未知单播），内核根据 MAC 地址查询 FDB 以确定目标 VTEP 的 IP 地址，然后数据包将直接发送到该 VTEP。FDB 中肯定存在该 MAC 地址所对应的 VTEP IP 地址，如果 FDB 中不存在则它不属于单播流量，而属于 BUM 流量（未知单播）。



**BUM 流量泛洪条目**

在 Linux 中，VXLAN 接口通过 ip link add 命令创建时，remote 参数只能指定**一个单播 VTEP IP 地址**。例如：

```
ip link add vxlan0 type vxlan id 42 remote 192.168.1.2 dev eth1 dstport 4789
```

- 这里只能设置一个 remote IP（192.168.1.2）。



在 VXLAN 接口创建时，remote（单播 IP）和 group（多播 IP）参数是**互斥的**，不能同时指定。例如：

```
ip link add vxlan100 type vxlan id 100 remote 10.10.10.10 group 239.1.1.1 dev eth1
```

- 以上命令会失败，因为内核不支持同时设置 remote 和 group。



虽然在使用 ip 命令创建 **vxlan** 接口时仅能指定**一个单播或组播 IP**，但配置 `remote IP / group IP` 其本质是告诉系统如何初始化或静态填充 **FDB** 表的 **BUM 流量泛洪条目** 。

可以通过手动配置 **vxlan** 接口的 **FDB** 表来达到配置多个单播 IP 或多个组播 IP，或同时配置多个单播 IP 和多个组播 IP。



VXLAN FDB 表中的匹配目标 MAC 地址为 `00:00:00:00:00:00` 的条目是 BUM 流量泛洪条目（flooding entry）。 `00:00:00:00:00:00` 表示“所有 MAC 地址”，是一个特殊的 MAC 地址，用于标识 BUM 流量（广播、未知单播、多播）的转发目标。

泛洪条目可以存在多条，可以指定单播 IP 和多播 IP，共同构成 **BUM 流量的目标列表**。

**BUM 流量**将通过头部复制发送到**单播 IP**。同时，**BUM 流量**也会发送到**多播组 IP**，由底层网络的多播协议分发到加入该组的 **VTEP**。

```
00:00:00:00:00:00 dst <VTEP_IP> self permanent
```



**动态学习**

默认情况下，VXLAN 启用动态学习。接收数据包时，内核从外层源 IP 和内层源 MAC 学习映射，更新 FDB。可以通过 nolearning 参数禁用学习，使用静态配置。

当第一次向某个 MAC 地址发送数据包时，**FDB** 表中不存在该 MAC 地址对应的 **VTEP**，因此该流量被视为 **BUM 流量（未知单播）**。**VXLAN** 接口会将此数据包泛洪到 **BUM 流量的目标列表（发送到所有 00:00:00:00:00:00 条目的 VTEP）**。

在所有接收到泛洪流量的节点中，只有一个节点拥有该 **MAC 地址**的设备，该设备会发送响应数据包。接收数据包时，内核从外层源 IP 和内层源 MAC 学习到该 MAC 地址对应的 **VTEP IP** 地址，并自动将其添加到 **FDB** 表中。下一次向该 MAC 地址发送数据包时，就只会将其发送给特定的 **VTEP**。



## ARP 代理

源 IP 与目标 IP 通信前需发送 ARP 请求以获取目标 IP 的 MAC 地址。ARP 请求为广播包，属于 VXLAN 中的 BUM（Broadcast, Unknown Unicast, Multicast）流量。若未启用 ARP 代理，VXLAN 会将 ARP 请求泛洪至 BUM 流量的目标列表。

若启用了 ARP 代理，当 VXLAN 接口收到 ARP 请求，且其邻居表（ARP 表）中包含目标 IP 对应的 MAC 地址，VXLAN 接口会代表目标主机回应 ARP 请求，提供相应的 MAC 地址，并丢弃该 ARP 数据包。若邻居表中无对应条目，则按未启用 ARP 代理的方式处理，将 ARP 请求泛洪至 BUM 目标列表。





## MISS 消息

在 VXLAN 网络中，MISS 消息是指当设备无法在本地转发表中找到匹配的转发信息时，触发的一种处理机制。MISS 消息分为 L2（二层）和 L3（三层），分别对应 MAC 地址和 IP 地址的查找失败场景。

内核在发现在 ARP 或者 FDB 表项中找不到相应的表项，则可以通过 NETLINK 消息发送通知，用户态进程可以监听相应消息并补充所缺失的表项记录，从而实现动态的表项维护。

**L2MISS**：VXLAN 设备在 FDB 表中找不到目的 MAC 地址所属的 VTEP IP 地址。L2MISS 消息的发送需要满足如下条件：

- 目的 MAC 地址在本地 FDB 表中不存在（即没有匹配的条目）
- FDB 表中没有 **MAC 地址字段为全零（00:00:00:00:00:00）表项**（BUM 流量泛洪条目）
- 目的 MAC 地址不是组播或多播地址

**L3MISS**：VXLAN 设备在 ARP 表中找不到目的 IP 所对应的 MAC 地址



注意：开启 MISS 消息后，仅在不存在对应的表项时发送通知，不会影响 **VXLAN 的数据转发机制**。





### flannel

linux1 ip 10.13.0.101

linux2 ip 10.13.0.102

linux3 ip 10.13.0.103



linux1

```
ip link add br0 type bridge
ip link set br0 up

ip link add vxlan type vxlan id 1 local 10.13.0.101 dstport 0
ip link set vxlan master br0 up

bridge fdb add 00:00:00:00:00:00 dst 10.13.0.102 dev vxlan
bridge fdb append 00:00:00:00:00:00 dst 10.13.0.103 dev vxlan
```



```
ip netns add pod1
ip link add pod1 type veth peer name eth0 netns pod1
ip link set pod1 master br0 up
```



```
ip netns exec pod1 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.10.10/24 dev eth0
ip route add 192.168.20.0/24 dev eth0 proto static src 192.168.10.10
ip route add 192.168.30.0/24 dev eth0 proto static src 192.168.10.10
```



linux2

```
ip link add br0 type bridge
ip link set br0 up

ip link add vxlan type vxlan id 1 local 10.13.0.102 dstport 0
ip link set vxlan master br0 up

bridge fdb add 00:00:00:00:00:00 dst 10.13.0.101 dev vxlan
bridge fdb append 00:00:00:00:00:00 dst 10.13.0.103 dev vxlan
```



```
ip netns add pod2
ip link add pod2 type veth peer name eth0 netns pod2
ip link set pod2 master br0 up
```



```
ip netns exec pod2 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.20.10/24 dev eth0
ip route add 192.168.10.0/24 dev eth0 proto static src 192.168.20.10
ip route add 192.168.30.0/24 dev eth0 proto static src 192.168.20.10
```



linux3

```
ip link add br0 type bridge
ip link set br0 up

ip link add vxlan type vxlan id 1 local 10.13.0.103 dstport 0
ip link set vxlan master br0 up

bridge fdb add 00:00:00:00:00:00 dst 10.13.0.101 dev vxlan
bridge fdb append 00:00:00:00:00:00 dst 10.13.0.102 dev vxlan
```



```
ip netns add pod3
ip link add pod3 type veth peer name eth0 netns pod3
ip link set pod3 master br0 up
```



```
ip netns exec pod3 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.30.10/24 dev eth0
ip route add 192.168.10.0/24 dev eth0 proto static src 192.168.30.10
ip route add 192.168.20.0/24 dev eth0 proto static src 192.168.30.10
```



### kube-proxy

linux1 ip 10.13.0.101

linux2 ip 10.13.0.102

linux3 ip 10.13.0.103



linux1

```
ip link add br0 type bridge
ip link set br0 up

ip link add vxlan type vxlan id 1 local 10.13.0.101 dstport 0
ip link set vxlan master br0 up

bridge fdb add 00:00:00:00:00:00 dst 10.13.0.102 dev vxlan
bridge fdb append 00:00:00:00:00:00 dst 10.13.0.103 dev vxlan
```



```
ip netns add pod1
ip link add pod1 type veth peer name eth0 netns pod1
ip link set pod1 master br0 up

ip address add 192.168.10.1/24 dev br0
ip route add 192.168.20.0/24 via 192.168.20.1 dev br0 onlink proto static src 192.168.10.1
ip route add 192.168.30.0/24 via 192.168.30.1 dev br0 onlink proto static src 192.168.10.1
```



```
ip netns exec pod1 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.10.10/24 dev eth0
ip route add default via 192.168.10.1 dev eth0 proto static src 192.168.10.10
ip route add 192.168.10.100/32 via 192.168.10.1 dev eth0 proto static src 192.168.10.10
```



在主命名空间中创建

```
# 创建 nat 表中的 KUBE-SERVICES 链
iptables -t nat -N KUBE-SERVICES

# 创建 KUBE-SVC-HTTP 链
iptables -t nat -N KUBE-SVC-HTTP

# 创建 KUBE-SEP-POD2 链
iptables -t nat -N KUBE-SEP-POD2

# 创建 KUBE-SEP-POD3 链
iptables -t nat -N KUBE-SEP-POD3

# PREROUTING 捕获所有进入节点的流量，跳转到 KUBE-SERVICES 链
iptables -t nat -A PREROUTING -j KUBE-SERVICES

# OUTPU 捕获所有进入节点的流量，跳转到 KUBE-SERVICES 链
iptables -t nat -A OUTPUT -j KUBE-SERVICES

# KUBE-SERVICES 链中捕获发送给 192.168.10.100:80 的 TCP 流量，跳转到 KUBE-SVC-HTTP
iptables -t nat -A KUBE-SERVICES -d 192.168.10.100/32 -p tcp --dport 80 -j KUBE-SVC-HTTP

# KUBE-SVC-HTTP 链中使用 statistic 模块，50% 概率跳转到 KUBE-SEP-POD2
iptables -t nat -A KUBE-SVC-HTTP -m statistic --mode random --probability 0.5 -j KUBE-SEP-POD2

# KUBE-SVC-HTTP 链中剩余流量（50% 概率）跳转到 KUBE-SEP-POD3
iptables -t nat -A KUBE-SVC-HTTP -j KUBE-SEP-POD3

# KUBE-SEP-POD2 链中 DNAT 到 192.168.20.10:80
iptables -t nat -A KUBE-SEP-POD2 -p tcp -j DNAT --to-destination 192.168.20.10:80

# KUBE-SEP-POD3 链中 DNAT 到 192.168.30.10:80
iptables -t nat -A KUBE-SEP-POD3 -p tcp -j DNAT --to-destination 192.168.30.10:80
```



linux2

```
ip link add br0 type bridge
ip link set br0 up

ip link add vxlan type vxlan id 1 local 10.13.0.102 dstport 0
ip link set vxlan master br0 up

bridge fdb add 00:00:00:00:00:00 dst 10.13.0.101 dev vxlan
bridge fdb append 00:00:00:00:00:00 dst 10.13.0.103 dev vxlan
```



```
ip netns add pod2
ip link add pod2 type veth peer name eth0 netns pod2
ip link set pod2 master br0 up

ip address add 192.168.20.1/24 dev br0
ip route add 192.168.10.0/24 via 192.168.10.1 dev br0 onlink proto static src 192.168.20.1
ip route add 192.168.30.0/24 via 192.168.30.1 dev br0 onlink proto static src 192.168.20.1
```



```
ip netns exec pod2 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.20.10/24 dev eth0
ip route add default via 192.168.20.1 dev eth0 proto static src 192.168.20.10

mkdir /opt/web/
echo "Welcome to Pod2!" > /opt/web/index.html
python3 -m http.server 80
```



linux3

```
ip link add br0 type bridge
ip link set br0 up

ip link add vxlan type vxlan id 1 local 10.13.0.103 dstport 0
ip link set vxlan master br0 up

bridge fdb add 00:00:00:00:00:00 dst 10.13.0.101 dev vxlan
bridge fdb append 00:00:00:00:00:00 dst 10.13.0.102 dev vxlan
```



```
ip netns add pod3
ip link add pod3 type veth peer name eth0 netns pod3
ip link set pod3 master br0 up

ip address add 192.168.30.1/24 dev br0
ip route add 192.168.10.0/24 via 192.168.10.1 dev br0 onlink proto static src 192.168.30.1
ip route add 192.168.20.0/24 via 192.168.20.1 dev br0 onlink proto static src 192.168.30.1
```



```
ip netns exec pod3 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.30.10/24 dev eth0
ip route add default via 192.168.30.1 dev eth0 proto static src 192.168.30.10

mkdir /opt/web/
echo "Welcome to Pod3!" > /opt/web/index.html
python3 -m http.server 80
```



