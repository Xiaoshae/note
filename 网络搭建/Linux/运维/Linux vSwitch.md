# open vSwitch

OpenvSwitch (简称 OVS) 是一个用 C 语言开发的多层虚拟交换机。现如今基本上已经成为了开源 SDN（软件定义网络）基础设施层的事实标准。

- 支持标准 802.1Q VLAN协议，允许端口配置trunk模式。
- 支持组播
- 支持多种隧道协议（GRE、VXLAN、STT、Geneve 和 IPsec）
- 支持内核和用户空间的转发引擎选项



术语解释

**Bridge**

中文名称**网桥**，一个 Bridge 代表一个以太网交换机（Switch），一台主机可以创建一个或多个 Bridge，Bridge 可以根据一定的规则，把某一个端口接收到的数据报文转发到另一个或多个端口上，也可以修改或丢弃数据报文。



**Port**

交换机上的插口，可以接水晶头，Port隶属于 Bridge，必须先添加了 Bridge 才能在 Bridge 上添加 Port。

>  **Normal**：用户可以把操作系统中已有的网卡添加到 OVS 上，OVS会自动生成一个同名的Port。此类型的 Port 常用于 VLAN 模式的多台物理主机相连的口，交换机的一端属于 Trunk 模式

>  **Internal**：当Port的类型是 Internal 时，OVS会自动创建一个虚拟网卡（Interface），此端口收到的数据报文都会转发到这个网卡。

>  **Patch**：Patch Port 和 veth pair 功能相同，总是成双成对的出现，在其中一端收到的数据报文会被转发到另一个 Patch Port 上，就像是一根网线一样，Patch Port 常用于链接两个 Bridge，使两个网桥合并成为一个网桥

>  **Tunnel**：OVS 支持 GRE、VXLAN、IPsec 隧道协议，这些隧道协议就是 overlay 网络的基础协议，通过对物理网络做的一层封装和扩展，解决跨二层网络的问题。



**Interface**

接口是 OVS 与操作系统交换数据报文的组件，一个接口即是操作系统上的一块网卡，这个网卡可能是 OVS 生成的虚拟网卡，也可能是挂载在 OVS 上的物理网卡，操作系统上的虚拟网卡（TAP/TUN）也可以被挂载在 OVS 上。



**Controller**

OpenFlow 控制器，OVS 可以接受一个或者多个 OpenFLow 控制器的管理。功能主要是下发流表、控制转发规则。



**Flow**

流表是OVS进行数据转发的核心功能，定义了端口之间的转发数据报文的规则，一条流表规则主要分为匹配和动作两部分，匹配部分决定哪些数据报文需要被处理，动作决定了匹配到的数据报文该如何处理。



基础命令

- 添加网桥：`ovs-vsctl add-br br0`
- 列出所有网桥：`ovs-vsctl list-br`
- 判断网桥是否存在：`ovs-vsctl br-exists br0`
- 将物理网卡挂接到网桥：`ovs-vsctl add-port br0 eth0`
- 列出网桥中的所有端口：`ovs-vsctl list-ports br0`
- 列出所有挂接到网卡上的网桥：`ovs-vsctl port-to-br eth0`
- 查看OVS 状态：`ovs-vsctl show`
- 查看OVS 的所有Interface、Port 等：`ovs-vsctl list (Interface|Port)` 或 `ovs-vsctl list Port ens37`
- 删除网桥上已经挂接的网口：`vs-vsctl del-port br0 eth0`
- 删除网桥：`ovs-vsctl del-br br0`



## vlan id

```
ip netns add vlan10-1
ip netns add vlan10-2


ip link add vlan10-1 type veth peer name eth0 netns vlan10-1
ip link add vlan10-2 type veth peer name eth0 netns vlan10-2


ip link set vlan10-1 up
ip link set vlan10-2 up
```



```
ip netns add vlan20-1
ip netns add vlan20-2

ip link add vlan20-1 type veth peer name eth0 netns vlan20-1
ip link add vlan20-2 type veth peer name eth0 netns vlan20-2

ip link set vlan20-1 up
ip link set vlan20-2 up
```



```
ip link add vlan10-patch type veth peer name vlan20-patch

ip link set vlan10-patch
ip link set vlan20-patch
```



```
ovs-vsctl add-br vlan10

ovs-vsctl add-port vlan10 vlan10-1
ovs-vsctl add-port vlan10 vlan10-2

ovs-vsctl set port vlan10-1 tag=10
ovs-vsctl set port vlan10-2 tag=10

ovs-vsctl add-port vlan10 vlan10-patch
```



```
ovs-vsctl add-br vlan20

ovs-vsctl add-port vlan20 vlan20-1
ovs-vsctl add-port vlan20 vlan20-2

ovs-vsctl set port vlan20-1 tag=20
ovs-vsctl set port vlan20-2 tag=20

ovs-vsctl add-port vlan20 vlan20-patch
```



```
ip netns exec vlan10-1 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.101/24 dev eth0
```



```
ip netns exec vlan10-2 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.102/24 dev eth0
```



```
ip netns exec vlan20-1 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.201/24 dev eth0
```



```
ip netns exec vlan20-2 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.202/24 dev eth0
```



## dhcp

```
apt install -y dnsmasq isc-dhcp-client 
```



```
systemctl stop dnsmasq
```



```
ip netns add dhcp
ip netns add main

ip link add dhcp type veth peer name eth0 netns dhcp
ip link add main type veth peer name eth0 netns main

ip link set dhcp up
ip link set main up

ovs-vsctl add-br br-dhcp
ovs-vsctl add-port br-dhcp dhcp
ovs-vsctl add-port br-dhcp main
```



```
ip netns exec dhcp bash

ip link set lo up
ip link set eth0 up
ip address add 192.168.100.1/24 dev eth0

dnsmasq \
    --no-daemon \
    --interface=eth0 \
    --dhcp-range=192.168.100.100,192.168.100.200,12h \
    --dhcp-option=option:router,192.168.100.1 \
    --dhcp-option=option:dns-server,223.5.5.5,223.6.6.6
dnsmasq: started, version 2.90 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq-dhcp: DHCP, IP range 192.168.100.100 -- 192.168.100.200, lease time 12h
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 127.0.0.53#53
dnsmasq: read /etc/hosts - 8 names
...

# 在 main 命名空间中执行 dhclient eth0 命令后
dnsmasq-dhcp: DHCPDISCOVER(eth0) b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPOFFER(eth0) 192.168.100.195 b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPDISCOVER(eth0) b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPOFFER(eth0) 192.168.100.195 b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPREQUEST(eth0) 192.168.100.195 b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPACK(eth0) 192.168.100.195 b6:23:6b:b7:02:36 u4-1
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 127.0.0.53#53
```



```
ip netns exec main bash

ip link set lo up
ip link set eth0 up

dhclient eth0

# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever

2: eth0@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether b6:23:6b:b7:02:36 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.100.195/24 brd 192.168.100.255 scope global dynamic eth0
       valid_lft 42719sec preferred_lft 42719sec
    inet6 fe80::b423:6bff:feb7:236/64 scope link 
       valid_lft forever preferred_lft forever
```



## 跨主机通讯

gre 是点对点通讯，gre 可以封装二层（数据链路层）流量。

gre 跨主机通讯

linux1 网卡 ip 10.13.0.101

linux2 网卡 ip 10.13.0.102



linux1

```
ovs-vsctl add-br br

ovs-vsctl add-port br gre
ovs-vsctl set interface gre type=gre options:remote_ip=10.13.0.102
```



```
ip netns add dhcp
ip link add dhcp type veth peer name eth0 netns dhcp
ip link set dhcp up
ovs-vsctl add-port br dhcp
```



```
ip netns exec dhcp bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.1/24 dev eth0

dnsmasq \
    --no-daemon \
    --interface=eth0 \
    --dhcp-range=192.168.100.100,192.168.100.200,12h \
    --dhcp-option=option:router,192.168.100.1 \
    --dhcp-option=option:dns-server,223.5.5.5,223.6.6.6

dnsmasq: started, version 2.90 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq-dhcp: DHCP, IP range 192.168.100.100 -- 192.168.100.200, lease time 12h
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 127.0.0.53#53
dnsmasq: read /etc/hosts - 8 names
...

# linux2 中的 main 命名空间中执行 dhclient eth0 后
dnsmasq-dhcp: DHCPDISCOVER(eth0) b6:88:e7:1f:5f:3d 
dnsmasq-dhcp: DHCPOFFER(eth0) 192.168.100.199 b6:88:e7:1f:5f:3d 
dnsmasq-dhcp: DHCPDISCOVER(eth0) b6:88:e7:1f:5f:3d 
dnsmasq-dhcp: DHCPOFFER(eth0) 192.168.100.199 b6:88:e7:1f:5f:3d 
dnsmasq-dhcp: DHCPREQUEST(eth0) 192.168.100.199 b6:88:e7:1f:5f:3d 
dnsmasq-dhcp: DHCPACK(eth0) 192.168.100.199 b6:88:e7:1f:5f:3d u4-2
```



linux2

```
ovs-vsctl add-br br

ovs-vsctl add-port br gre
ovs-vsctl set interface gre type=gre options:remote_ip=10.13.0.101
```



```
ip netns add main
ip link add main type veth peer name eth0 netns main
ip link set main up
ovs-vsctl add-port br main
```



```
ip netns exec main bash

ip link set lo up
ip link set eth0 up

dhclient eth0
```



## gre openstack

openstack 组网

linux1 网卡1（ens33） 192.168.20.180 （能上外网）

linux1 网卡2 10.13.0.101 （内网通讯）



linux2 网卡1 10.13.0.102 （内网通讯）



linux3 网卡1 10.13.0.103 （内网通讯）



linux1

```
ip netns add forward

ip link add dhcp type veth peer name eth0 netns forward
ip link add net-ext type veth peer name eth1 netns forward

ip link set dhcp up
ip link set net-ext up
```



```
ovs-vsctl add-br br-int

ovs-vsctl add-port br-int gre1
ovs-vsctl add-port br-int gre2

ovs-vsctl set interface gre1 type=gre options:remote_ip=10.13.0.102
ovs-vsctl set interface gre2 type=gre options:remote_ip=10.13.0.103

ovs-vsctl add-port br-int dhcp
```



```
ovs-vsctl add-br br-ext

ovs-vsctl add-port br-ext ens33
ovs-vsctl add-port br-ext net-ext

ip link set br-ext up
ip address add 192.168.20.180/24 dev br-ext
```



```
ip netns exec forward bash

ip link set lo up
ip link set eth0 up
ip link set eth1 up

ip address add 192.168.100.1/24 dev eth0
ip address add 192.168.20.254/24 dev eth1

ip route add default via 192.168.20.180 dev eth1 src 192.168.20.254 proto static

dnsmasq \
    --no-daemon \
    --interface=eth0 \
    --dhcp-range=192.168.100.100,192.168.100.200,12h \
    --dhcp-option=option:router,192.168.100.1 \
    --dhcp-option=option:dns-server,223.5.5.5,223.6.6.6

```



```
# 主网络命名空间

ip route add default via 192.168.20.2 dev br-ext proto static metric 1

ip route add 192.168.100.0/24 via 192.168.20.254 dev br-ext src 192.168.20.180 proto static

iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o br-ext -j MASQUERADE
```





linux2

```
ip netns add main

ip link add main type veth peer name eth0 netns main

ip link set main up
```



```
ovs-vsctl add-br br-int

ovs-vsctl add-port br-int gre

ovs-vsctl set interface gre type=gre options:remote_ip=10.13.0.101

ovs-vsctl add-port br-int main
```



```
ip netns exec main bash

ip link set lo up
ip link set eth0 up

dhclient eth0
```



linux3

```
ip netns add main

ip link add main type veth peer name eth0 netns main

ip link set main up
```



```
ovs-vsctl add-br br-int

ovs-vsctl add-port br-int gre

ovs-vsctl set interface gre type=gre options:remote_ip=10.13.0.101

ovs-vsctl add-port br-int main
```



```
ip netns exec main bash

ip link set lo up
ip link set eth0 up

dhclient eth0
```



## OpenFlow

OpenFlow 是一种网络通信协议，应用于SDN架构中控制器和转发器之间的通信。软件定义网络 SDN 的一个核心思想就是“转发、控制分离”，要实现转、控分离，就需要在控制器与转发器之间建立一个通信接口标准，允许控制器直接访问和控制转发器的转发平面。OpenFlow 引入了“**流表**”的概念，转发器通过流表来指导数据包的转发。



**工作原理**

整个OpenFlow协议架构由**控制器（Controller）**、**OpenFlow 交换机（OpenFlow Switch）**、以及安全通道（Secure Channel）组成。控制器对网络进行集中控制，实现控制层的功能；OpenFlow 交换机负责数据层的转发，与控制器之间通过安全通道进行消息交互，实现表项下发、状态上报等功能。

**OpenFlow 控制器**位于SDN架构中的控制层，通过 OpenFlow 协议指导 OpenFlow 交换机的如何进行数据转发。

**OpenFlow 安全通道**就是连接OpenFlow交换机与控制器的信道，负责在OpenFlow交换机和控制器之间建立安全链接。控制器通过这个通道来控制和管理交换机，同时接收来自交换机的反馈。



**OpenFlow 交换机**

OpenFlow 交换机是整个 OpenFlow 网络的核心部件，主要负责数据层的转发。OpenFlow 交换机可以是物理的交换机/路由器，也可以是虚拟化的交换机/路由器。按照对 OpenFlow 的支持程度，OpenFlow 交换机可以分为两类：

- OpenFlow 专用交换机：一个标准的 OpenFlow 设备，仅支持 OpenFlow 转发。他不支持现有的商用交换机上的正常处理流程，所有经过该交换机的数据都按照 OpenFlow 的模式进行转发。
- OpenFlow 兼容型交换机：既支持 OpenFlow 转发，也支持正常二三层转发。这是在商业交换机的基础上添加流表、安全通道和OpenFlow 协议来获得了 OpenFlow 特性的交换机。

OpenFlow交换机在实际转发过程中，依赖于流表（Flow Table）。流表是 OpenFlow 交换机进行数据转发的策略表项集合，指示交换机如何处理流量，所有进入交换机的报文都按照流表进行转发。流表本身的生成、维护、下发完全由控制器来实现。



**表流**

在传统网络设备中，交换机/路由器的数据转发需要依赖设备中保存的二层MAC地址转发表、三层IP地址路由表以及传输层的端口号等。OpenFlow交换机中使用的“流表”也是如此，不过他的表项并非是指普通的IP五元组，而是整合了网络中各个层次的网络配置信息，由一些关键字和执行动作组成的灵活规则。

OpenFlow 流表的每个流表项都由匹配域（Match Fields）、处理指令（Instructions）等部分组成。流表项中最为重要的部分就是匹配域和指令，当OpenFlow交换机收到一个数据包，将包头解析后与流表中流表项的匹配域进行匹配，匹配成功则执行指令。

流表项的结构随着OpenFlow版本的演进不断丰富，不同协议版本的流表项结构如下。

![流表项组成](./images/Linux%20vSwitch.assets/openflow_version.png)



**多级流表与流水线处理**

OpenFlow v1.0采用单流表匹配模式，这种模式虽然简单，但是当网络需求越来越复杂时，各种策略放在同一张表中显得十分臃肿。这使得控制平面的管理变得十分困难，而且随着流表长度与数目的增加，对硬件性能要求也越来越高。



从OpenFlow v1.1开始引入了多级流表和流水线处理机制，当报文进入交换机后，从序号最小的流表开始依次匹配，报文通过跳转指令跳转至后续某一流表继续进行匹配，这样就构成了一条流水线。多级流表的出现一方面能够实现对数据包的复杂处理，另一方面又能有效降低单张流表的长度，提高查表效率。

![多级流表处理流程](./images/Linux%20vSwitch.assets/download-1747637934934-4.png)



OpenFlow 支持多流表（Multi-Table Pipeline），每个流表都拥有一个唯一的编号（Table ID）。**表流**中的每个**流表项**（Flow Entry）包含一个优先级字段，**优先级高的流表项将被优先匹配**。

数据包进入交换机后，会按照流表编号从小到大的顺序依次经过每个流表进行匹配和处理，最初进入编号最小的流表（通常为 Table 0）。

在某个流表中，交换机会依据**流表项的优先级**从高到低进行匹配尝试。优先级以数值表示，范围通常为 0 到 65535，**数值越大优先级越高**。

- 如果匹配成功，执行对应的动作（可能包括跳转到另一个流表）。

- 如果没有匹配项，数据包会进入下一个编号的流表，或者根据流表的“Table-Miss”规则处理（例如丢弃或发送给控制器）。



在 OpenFlow 中，每个流表项（Flow Entry）主要由**匹配字段（Match Fields）**和**动作集（Action Set）**组成。

匹配字段决定数据包是否符合条件（是否被匹配），动作集或指令则定义匹配后如何处理数据包。



**匹配字段**

用于定义数据包的匹配条件。匹配字段指定了数据包的哪些头部字段或元数据需要被检查，以及这些字段的具体值或范围。

常见的匹配字段包括：

- 源和目标 MAC 地址
- 源和目标 IP 地址
- 源和目标端口号
- 协议类型（如 TCP、UDP）
- VLAN ID、优先级
- 输入端口（Ingress Port）
- 元数据（Metadata，用于在流表间传递信息）



**动作集**

用于定义数据包匹配成功后需要执行的操作。数据包匹配成功后，可按顺序执行多个动作。每个动作被称为一个动作项，而多个动作项共同构成**动作集**。



在 OpenFlow 1.0 中，流表项直接关联一个动作列表（Actions），例如转发到某个端口、修改包头、丢弃等。



从 OpenFlow 1.1 开始，引入了指令（Instructions）的概念，指令可以包含多个动作（Action Set），并且支持更复杂的处理逻辑，例如：

- **Apply-Actions**：立即应用一组动作。
- **Write-Actions**：将动作写入动作集，延迟执行。
- **Goto-Table**：跳转到另一个流表。
- **Write-Metadata**：写入元数据。



**动作集中的动作**可以根据其性质和执行效果分为两类：一种是**非终止性动作**，执行后允许**继续匹配**或处理的动作；另一种是**终止性动作**执，行后会**终止匹配**或处理流程的动作。



**非终止性动作**，常见的动作包括：

- **修改数据包字段（Modify-Field Actions）**：例如修改 MAC 地址、IP 地址、端口号等。执行这类动作后，数据包会以修改后的内容继续参与匹配或处理。
- **写入动作集（Write-Actions）**：将某些动作写入动作集，但不立即执行，数据包可以继续处理。
- **写入元数据（Write-Metadata）**：写入一些元数据供后续流表使用，数据包继续处理。
- **Goto-Table**：跳转到另一个流表进行匹配。这是一个显而易见的继续处理流程的指令。



**终止性动作**，常见的动作包括：

- **输出（Output）**：将数据包转发到某个端口（或控制器）。一旦数据包被转发，通常不会再回到流表进行匹配（除非是特殊情况，如转发到内部端口）。
- **丢弃（Drop）**：显式丢弃数据包，处理流程直接终止。
- **组动作（Group）**：如果组动作最终导致数据包被输出或丢弃，处理流程也会终止。
- **发送到控制器（Packet-In）**：将数据包发送给控制器处理，通常也会终止交换机内部的匹配流程。



### ovs

关于当前 OVS 版本支持的所有**匹配字段和动作集**，建议查看 **man ovs-ofctl** 中 **Flow Syntax** 部分的详细解释。重点在于掌握编写 flow 的语法规则，这样在具体使用某个字段时，可以快速通过 man 手册查找并测试其具体用法。



### Flow Syntax

Flow 语法由一系列 `field=value` 的赋值语句组成，字段和值之间用等号 `=` 连接，多个赋值语句之间可以用逗号 `,` 或空格分隔。如果描述中包含空格，通常需要用引号将整个描述包裹起来，以防止 shell 将其拆分为多个参数。

示例：

```
dl_type=0x0800,nw_src=192.168.1.1,nw_dst=192.168.1.2,actions=output:1
```



`ovs-ofctl` 命令还支持一些额外的键值对，用于控制流表操作或指定流的行为。以下是主要的特殊字段和选项：



### 特殊字段

#### table

`table=table`

在操作流表项（如添加、删除、修改流）时，可以通过 `table=table` 参数指定操作针对哪个具体的流表。`table` 可以是一个数字（0 到 255），也可以是一个表名（如果交换机支持表名且未使用 `--no-names` 选项）。



在**查询流表项**时，未指定表（或指定 `table=255`），命令会返回**所有表**中的流表项。操作对象为 “所有表”

在**插入流表项**时，未指定表（或指定 `table=255`），命令会操作**默认表（table=0）**的流表项。

在**修改或删除流表项**时，未指定表（或指定 `table=255`），具体行为取决于是否使用了 --strict 参数

- 如果**不使用**该参数，该命令将应用于所有表中匹配的流。
- 如果**使用**该参数，该命令将仅对任意一个表中的单个匹配流进行操作；如果多个表中有匹配项，则命令不会执行任何操作。





#### priority

**priority=value**：设置流的**（显示）优先级**，value 范围为 0 到 65535，默认为 32768。

精确匹配的流（即匹配条件中没有通配符，所有字段都明确指定），其**隐式优先级等同于 65535**（最高优先级）。



显式优先级（Explicit Priority）是指用户通过 `priority=value` 明确为流表项指定的优先级，值范围为 0 到 65535，值越大优先级越高。如果未指定，默认显式优先级为 32768。

隐式优先级（Implicit Priority）是指在 OpenFlow 流表匹配中，**精确匹配的流隐式优先级**等同于 65535。**非精确匹配的流没有隐式优先级。**



在 OpenFlow 和 Open vSwitch 中，匹配流表项时，交换机会按照以下规则比较优先级：

1. **精确匹配优先**：如果一个流表项为**精确匹配**，其隐式优先级等同于 **65535**，**精确匹配的流优先于任何非精确匹配的流表项**，即使后者的显式优先级设置得再高。
2. **比较优先级**：如果两个流表项都属于精确匹配（或都属于非精确匹配），则会比较它们的显式优先级，**显式优先级较高的流表项将优先被匹配**。
3. **显式优先级相同时的匹配行为**：如果两个流表项的隐式优先级和显式优先级都相同，OpenFlow 规范未定义匹配行为，具体取决于交换机的实现



首先，系统会匹配所有**精确匹配流表项**。如果存在多个精确匹配流表项，则会比较它们的**显式优先级**，优先匹配显式优先级较高的流表项。

其次，系统会匹配所有**非精确匹配流表项**。同样，如果存在多个非精确匹配流表项，则会比较它们的**显式优先级**，优先匹配显式优先级较高的流表项。



#### cookie

`cookie` 是一个 64 位的标识符（**即一个 64 位整数**），用于标识或标记一组流（flow entries）。它本质上是一个用户自定义的标签，控制器或管理员可以利用这个标签来管理或操作流表中的特定流。

它并不影响流的匹配逻辑或数据包的处理行为，而是作为一种元数据（metadata），方便对流进行分组、查找、修改或删除。



`cookie=value`

这种形式用于为流指定一个具体的 cookie 值，通常用于添加或修改流时，将某个特定的值关联到流上。



` cookie=value/mask`

这种形式用于匹配或操作具有特定 cookie 值的流，`mask` 是一个 64 位的掩码，用于指定哪些位需要精确匹配，哪些位可以通配。

通常用于在查询时通过 cookie 匹配某一组流。



#### 存活时间

**idle_timeout=seconds**

指定了一个流表项在没有匹配到任何数据包（即非活动状态）的情况下可以存活的秒数。如果在指定的时间内没有数据包匹配该流表项，流表项会过期并被删除。默认为 0（不超时）。



**hard_timeout=seconds**

指定了一个流表项无论是否活跃（即是否匹配到数据包），在指定秒数后都会过期并被删除。默认为 0（无硬性截止日期）。



#### 驱逐

在网络交换机中，流表（Flow Table）是一个有限的资源，用于存储数据包的转发规则（流表项）。当流表空间不足以容纳新的流表项时，交换机需要删除一些旧的流表项来为新流表项腾出空间，这个删除旧流表项的过程就称为“驱逐”。



**importance=value**

设置流的重要性，value 范围 0-65535，默认为 0（不可驱逐）。



#### 状态信息

`duration=..., n_packet=..., n_bytes=...`

这些字段用于显示流的状态信息（如持续时间、数据包数量、字节数量），在 `dump-flows` 输出中可见。

`ovs-ofctl` 在解析输入时会忽略这些字段，因此可以将 `dump-flows` 的输出直接作为其他命令的输入。



#### action

`actions=[action][,action...]`

指定匹配流后执行的动作，多个动作用逗号分隔。如果未指定动作，匹配的数据包将被丢弃。

具体动作的语法和语义参见 `ovs-actions(7)` 手册



### 匹配字段

具体匹配字段的语法和语义参见 `ovs-fields(7)` 手册



#### 规范化形式 (Normal Form)

规范化形式是 OpenFlow 流匹配的一个重要概念，确保流的指定符合协议层次结构。规范化形式要求：

- 一个流只能在指定特定 L2 协议（如 Ethernet）的情况下匹配 L3 字段（如 ip_src、ip_dst）。
- 匹配 L4 字段（如 tcp_src、tcp_dst）时，必须同时指定特定 L2 和 L3 协议类型。



“aka” 是 “also known as” 的缩写，意思是“也被称为”或“又名”。



#### ethernet (Layer 2)

**eth_src (aka dl_src)**：Ethernet 源地址，48 位，格式为 Ethernet 地址 (xx:xx:xx:xx:xx:xx)，支持任意位掩码匹配。用于匹配数据包的源 MAC 地址。

**eth_dst (aka dl_dst)**：Ethernet 目标地址，48 位，格式为 Ethernet 地址，支持任意位掩码匹配。用于匹配数据包的目的 MAC 地址。



掩码（Mask）是一种用于过滤或匹配数据的位模式。

- 掩码位为 `1`：表示这一位是需要匹配的，地址的这一位必须与规则中指定的值一致。
- 掩码位为 `0`：表示这一位是“通配符”，地址的这一位可以是任意值（0 或 1），不影响匹配结果。



单播地址：第一个字节的最低位（LSB, Least Significant Bit）为 **0**，表示这是一个单播地址。

组播地址：第一个字节的最低位（LSB, Least Significant Bit）为 **1**，表示这是一个组播地址。

广播地址：固定为全 1 的地址：`FF:FF:FF:FF:FF:FF`

| 类型           | MAC 地址            | 掩码 (Mask)         | 说明                             |
| -------------- | ------------------- | ------------------- | -------------------------------- |
| 单播地址       | `00:00:00:00:00:00` | `01:00:00:00:00:00` | 第一个字节最低位为 0             |
| 广播和组播地址 | `01:00:00:00:00:00` | `01:00:00:00:00:00` | 第一个字节最低位为 1（包括广播） |
| 仅广播地址     | `FF:FF:FF:FF:FF:FF` | `FF:FF:FF:FF:FF:FF` | 精确匹配全 1 地址                |



**eth_type (aka dl_type)**：Ethernet 类型，16 位，格式为十六进制，不支持掩码匹配。用于标识数据包的协议类型（如 0x0800 表示 IPv4，0x86dd 表示 IPv6，0x8100 表示携带 vlan id 802.1Q 标准）。



带 VLAN 标签的以太网帧在 MAC 地址后插入一个 4 字节的 802.1Q 标签，标签的 EtherType 为 **0x8100**。

802.1Q 标签之后会有另一个 EtherType 字段，指示实际载荷的协议类型。对于 IPv4 数据包，此字段通常是 **0x0800**。

eth_type（或 dl_type）字段指的是**载荷的协议类型**，而不是 802.1Q 标签的 EtherType。因此，即使帧携带 VLAN 标签，OVS 会解析 802.1Q 标签后的 EtherType 来确定 eth_type。



#### arp

> 前提条件：ARP 包（eth_type=0x0806）

**arp_sha**：发送者硬件地址（MAC，48 位），支持掩码。

**arp_tha**：目标硬件地址（MAC，48 位），支持掩码。

**arp_spa**：发送者协议地址（IP，32 位），支持掩码。

**arp_tpa**：目标协议地址（IP，32 位），支持掩码。

**arp_op**：ARP 操作码（16 位），如 1 表示请求，2 表示应答。



#### ip (Layer 3)

> 前提条件：IPv4 包 (eth_type=0x0800)。

**ip_src (aka  nw_src)**：IPv4 源地址，32 位，格式为 IPv4 地址 (a.b.c.d)，支持任意位掩码匹配（包括 CIDR 格式）。用于匹配 IPv4 数据包的源 IP 地址。

**ip_dst (aka nw_dst)**：IPv4 目标地址，32 位，格式为 IPv4 地址，支持任意位掩码匹配。用于匹配 IPv4 数据包的目的 IP 地址。



> 前提条件：IPv6 包 (eth_type=0x86dd)。

**ipv6_src**：IPv6 源地址，128 位，格式为 IPv6 地址，支持任意位掩码匹配。用于匹配 IPv6 数据包的源 IP 地址。

**ipv6_dst**：IPv6 目标地址，128 位，格式为 IPv6 地址，支持任意位掩码匹配。用于匹配 IPv6 数据包的目的 IP 地址。



**nw_proto (aka ip_proto)**：IP 协议类型，8 位，格式为十进制，不支持掩码匹配。用于匹配 IPv4 或 IPv6 数据包的协议类型（如 6 表示 TCP，17 表示 UDP）。



#### Layer 4

> 前提条件：TCP 包 (nw_proto=6)。

**tcp_src (或 tp_src)**：TCP 源端口，16 位，格式为十进制，支持任意位掩码匹配。用于匹配 TCP 数据包的源端口。

**tcp_dst (或 tp_dst)**：TCP 目标端口，16 位，格式为十进制，支持任意位掩码匹配。用于匹配 TCP 数据包的目的端口。



> 前提条件：UDP 包 (nw_proto=17)。

**udp_src**：UDP 源端口，16 位，格式为十进制，支持任意位掩码匹配。用于匹配 UDP 数据包的源端口。

**udp_dst**：UDP 目标端口，16 位，格式为十进制，支持任意位掩码匹配。用于匹配 UDP 数据包的目的端口。



#### 元数据字段

**in_port**：输入端口，16 位，格式为 OpenFlow 1.0 端口号，不支持掩码匹配。表示数据包进入交换机的端口号。

**in_port_oxm**：输入端口（扩展），32 位，格式为 OpenFlow 1.1+ 端口号，不支持掩码匹配。提供更大的端口号范围。



#### VLAN 字段

**vlan_vid**：VLAN ID，16 位（仅低 12 位有效），格式为十进制，支持任意位掩码匹配。用于匹配 802.1Q 头部中的 VLAN ID。

**vlan_pcp**：VLAN 优先级，8 位（仅低 3 位有效），格式为十进制，不支持掩码匹配。用于匹配 802.1Q 头部中的优先级。



### 动作集

具体动作的语法和语义参见 `ovs-actions(7)` 手册



**output:PORT**

数据包从端口 PORT 发出，PORT 为 openflow 端口号，若 PORT 为数据包进入端口，则不执行此 action。



**normal**

数据包交由 OVS 自身的转发规则完成转发，不再匹配任何 openflow flow。



**all**

数据包从网桥上所有端口发出，除了其进入端口。



**drop**

丢弃数据包，当然，drop 之后不能再跟其它 action。



**mod_vlan_vid:vlan_vid**

添加或修改数据包中的 VLAN tag 为此处指定的 tag。



**strip_vlan**

移除数据包中的 VLAN tag，如果有的话。



**mod_dl_src:mac**

修改源 MAC 地址。



**mod_dl_dst:mac**	

修改目的 MAC 地址。



**mod_nw_src:ip**

修改源 ip 地址。



**mod_nw_dst:ip**

修改目的 ip 地址。



**mod_tp_src:port**

修改 TCP 或 UDP 数据包**源端口号。**



**mod_tp_dst:port**

修改 TC P或 UDP 数据包**目的端口号**。



**resubmit([port],[table])**

若 port 指定，替换数据包 in_port 字段，并重新匹配（**从指定的流表（或默认流表）的第一条流表项开始进行匹配**。）

若 table 指定，提交数据包到指定 table，并匹配。
