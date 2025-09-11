# Router

在 Linux 系统中，路由管理主要依赖 iproute2 工具集中的 **ip route** 命令。在深入探讨 **ip route** 命令的具体用法前，我们先来了解 **ip route help** 输出的命令参数格式。熟悉帮助信息中对参数的描述方式，将有助于更好地理解和掌握这一命令的使用技巧。



## 参数格式

**ip route help** 命令输出的帮助信息中，部分内容如下。

```
ip route { add | del | change | append | replace } ROUTE

ROUTE := NODE_SPEC [ INFO_SPEC ]

NODE_SPEC := [ TYPE ] PREFIX [ tos TOS ]
             [ table TABLE_ID ] [ proto RTPROTO ]
             [ scope SCOPE ] [ metric METRIC ]
             [ ttl-propagate { enabled | disabled } ]

INFO_SPEC := { NH | nhid ID } OPTIONS FLAGS [ nexthop NH ]...

FAMILY := [ inet | inet6 | mpls | bridge | link ]
```



**ip route help** 的输出是一种命令行工具的语法描述，常用于 Linux 网络工具（如 **ip** 命令）的帮助信息。它采用了一种类似 BNF（巴科斯-诺尔范式）的形式，或者说是一种结构化的伪语法，用于清晰地描述命令的用法和参数。



### 参数顺序

参数的顺序**从左到右是完全固定的**，在下面的示例中，必须先出现 **route** 参数，才能出现 **add** 参数。

实际上 ip route 命令允许一定程度的**参数顺序错误**，它能自动识别和修正。

```
ip route add ...
```



### 定义符号

`:=` 是一种定义符号，用于表示“被定义为”或“由以下部分组成”。

在下面示例中，ROUTE 参数由 **NODE_SPEC 和可选的 INFO_SPEC** 组成。

```
ROUTE := NODE_SPEC [ INFO_SPEC ]
```



### 占位符

大写参数是**占位符**或**抽象概念**，需要替换为具体的值或进一步分解为子参数。特别地，**ROUTE** 实际上会被替换为 **NODE_SPEC [ INFO_SPEC]**，因此下面的两个示例在语法上等价：

```
ip route { add | del | change | append | replace } ROUTE

ROUTE := NODE_SPEC [ INFO_SPEC ]
```

```
ip route { add | del | change | append | replace } NODE_SPEC [ INFO_SPEC ]
```



### 关键字

小写参数是**实际的关键字**或**命令中的固定字符串**，，用户需要按原样输入，直接在命令中使用。

```
ip route add ...
```

- 其中 **add** 是小写关键字，必须按原文输入。



### 可选参数

**方括号 [ ]** 表示可选参数，即括号中的内容可以包含在命令中，也可以省略。

`[ INFO_SPEC ]` 表示 INFO_SPEC是可选的，命令在不包含该参数时仍然有效。

```
ROUTE := NODE_SPEC [ INFO_SPEC ]
```



### 多可选参数

方括号 [ ]，这些选项之间是互斥的，**可以选择一个，也可以完全不选择**（因为整个结构是可选的）。

下面示例表示可以选择 onlink 或 pervasive 参数，也可以不选择参数。

```
[ onlink | pervasive ]
```



### 多个参数选其一

**大括号 {}** 表示一组选项，这些选项之间是互斥的，必须从中选择一个。**竖线 |** 则表示“或”，用于分隔不同的选项。

在下面示例中，**{ add | del | change | append | replace }** 表示命令必须从 add、del、change、append 或 replace 中选择一个。

```
ip route { add | del | change | append | replace } ROUTE
```



### 重复参数

**...（省略号）**表示可以重复前面的元素或模式，通常用于表示列表或序列可以有多个实例。

下面示例中，[ nexthop NH ] ... 表示可以有零个或多个 nexthop NH。

```
INFO_SPEC := { NH | nhid ID } OPTIONS FLAGS [ nexthop NH ] ...
```



**STRING**：表示一个用户提供的字符串，通常是名称或标识符。

**NUMBER**：表示一个用户提供的数字，通常是整数。

**ADDRESS**：表示 IP 地址（IPv4 或 IPv6）。

**PREFIX**：表示 IP 前缀（地址加掩码长度），如 10.0.0.0/24 或 default。

**BOOL**：表示布尔值，通常是 true 或 false，在某些参数中可能用其他形式（如 1 或 0）。

**TIME**：表示时间值，可能带单位（如 s, ms）。



## ROUTE

ip route 主要由 **NODE_SPEC** 和 **INFO_SPEC** 两部分组成。其中，**NODE_SPEC** 是必选参数，用于定义路由的目标地址（**PREFIX**）以及基本行为（**TYPE**、**scope** 等）。而 **INFO_SPEC** 则是可选参数，主要用于指定到达目标的路径（**via**、**dev**）和相关优化参数（**mtu** 等）。

```
ROUTE := NODE_SPEC [ INFO_SPEC ]
```



## NODE_SPACE

**NODE_SPEC** 定义路由的目标地址（**PREFIX**）以及基本行为（**TYPE**、**scope** 等）。

```
NODE_SPEC := [ TYPE ] PREFIX [ tos TOS ]
         [ table TABLE_ID ] [ proto RTPROTO ]
         [ scope SCOPE ] [ metric METRIC ]
         [ ttl-propagate { enabled | disabled } ]
```



### TYPE

`[ TYPE ]` 参数（可选参数）指定路由类型，定义了数据包的处理方式。如果不指定，默认为 unicast。

```
TYPE := [ unicast | local | broadcast | multicast | throw | unreachable | prohibit | blackhole | nat ]
```



以下是几种主要路由类型：



**unicast（单播）**

单播路由描述了通往目标地址（由路由前缀覆盖）的实际网络路径。当数据包的目的地址匹配单播路由的前缀时，系统会根据路由条目（如下一跳、网关等）将数据包转发到正确的网络接口或目标。



**local（本地）**

表示目标地址属于本地主机，数据包会被回环并在本地处理。数据包不会通过网络接口发送，而是直接在本地协议栈中处理，类似 loopback 接口的行为。



**unreachable（不可达）**

表示目标地址不可达，数据包会被丢弃，并向发送方返回 ICMP “主机不可达”错误（EHOSTUNREACH）。

当路由表匹配到不可达路由时，系统会丢弃数据包，并生成 ICMP 错误消息，通知发送方目标无法到达。



**blackhole（黑洞）**

目标地址不可达，数据包会被无声丢弃，不生成任何错误消息。



**prohibit（禁止）**

目标地址被行政禁止，数据包会被丢弃，并向发送方返回 ICMP “通信被行政禁止”错误（EACCES）。



示例：

```
ip route add unicast 192.168.100.0/24 via 192.168.100.254
```



### PREFIX

PREFIX 表示路由的目标地址前缀，通常以 IP 地址（IPv4 或 IPv6）加前缀长度（prefix length）的形式表示，格式为 ADDRESS/PREFIXLEN。例如：

- IPv4 示例：`192.168.1.0/24`
- IPv6 示例：`2001:db8::/32`



如果省略前缀长度（即不指定 /PREFIXLEN），ip route 命令会假设是一个完整的单主机路由（host route），即：

- 对于 IPv4，前缀长度默认为 /32（匹配单一 IP 地址）。
- 对于 IPv6，前缀长度默认为 /128。



此外，PREFIX 还支持特殊值 **default**，表示默认路由，等价于：

- IPv4：`0.0.0.0/0`
- IPv6：`::/0`



示例：

```
ip route add 192.168.100.0/24 via 192.168.100.254
```

```
ip route add 0.0.0.0/0 via 192.168.100.254
```

```
ip route add default via 192.168.100.254
```

- PREFIX 为 default，等价于 0.0.0.0/0。





### TOS

`[ tos TOS ]` 参数（可选参数）。



服务类型（Type of Service，TOS）键。此键没有关联的掩码，其最长匹配规则如下：首先比较路由的 TOS 值和数据包的 TOS 值。如果两者不相等，数据包仍可能匹配 TOS 值为零的路由。



TOS（Type of Service）是 **IPv4 数据包头部中的一个 8 位字段**，位于 IP 头的第 8 位到第 15 位（从 0 开始计数）。

**原始定义（RFC 791, 1981）**，TOS（Type of Service）：

TOS 字段由 8 位组成，其中：

- **前 3 位**：优先级（Precedence，0-7），表示数据包的重要性。
- **后 4 位**：服务类型标志（D、T、R、C），分别表示低延迟（Delay）、高吞吐量（Throughput）、高可靠性（Reliability）和低成本（Cost）。
- **最后 1 位**：保留位，通常为 0。





**现代定义（RFC 2474, DiffServ, 1998）**TOS 字段被重新定义为 **Differentiated Services Field（DS Field）**，其中：

- **前 6 位**：Differentiated Services Code Point（DSCP），用于指定服务类别。
- **后 2 位**：Explicit Congestion Notification（ECN），用于拥塞控制。

```
+-+-+-+-+-+-+-+-+
|0|1|2|3|4|5|6|7|
+-+-+-+-+-+-+-+-+
|    DSCP   |ECN|
+-+-+-+-+-+-+-+-+
```



在 Linux 的 ip route 命令中，tos TOS 参数允许使用符号名称（如 lowdelay、EF）来表示 TOS（Type of Service）或 DSCP（Differentiated Services Code Point）值。这些符号名称的定义存储在两个配置文件中：**/etc/iproute2/rt_dsfield** 和 **/usr/share/iproute2/rt_dsfield**。

这两个文件的主要功能是为 ip route 命令中的 **tos TOS 参数**提供 TOS/DSCP 值的符号名称映射，使用户能够使用易于理解的名称（如 **lowdelay** 或 **EF**），而无需直接输入复杂的十六进制值（如 0x10 或 0x2e）。

以下是 **/etc/iproute2/rt_dsfield** 文件内容（部分）：

```
# Differentiated field values
# These include the DSCP and unused bits
0x0	default
# Newer RFC2597 values
0x28	AF11
...

# Older values RFC2474
0x20	CS1
...

# RFC 2598
0xB8	EF

# Deprecated values dropped upstream
# Kept in RHEL for backwards-compatibility
0x00   default
0x10   lowdelay
...

# This value overlap with ECT, do not use it!
0x02   mincost

# These values seems do not want to die, Cisco likes them by a strange reason.
0x20   priority
...
```



示例：

```
ip route add default tos 0x0 via 192.168.100.254
```

```
ip route add default tos default via 192.168.100.254
```



### table

`[ table TABLE_ID ]` 参数（可选参数）。

```
TABLE_ID := [ local | main | default | all | NUMBER ]
```



在 Linux 系统中，路由表（routing table）是内核用来决定数据包转发路径的数据库。默认情况下，系统使用一个主要的路由表（通常称为 `main` 表，ID 为 254）。但是，Linux 支持多个路由表，每个路由表可以有自己的路由规则，适用于不同的网络策略或虚拟路由转发（VRF）场景。



`TABLE_ID` 可以是以下几种形式：

- 预定义的路由表名称：
  - `local`：ID 为 255，是一个特殊的路由表，包含本地地址和广播地址的路由条目。内核自动维护这个表，管理员通常不需要手动修改。
  - `main`：ID 为 254，是默认的路由表，普通的路由条目通常都存储在这个表中。内核在计算路由时默认使用这个表。
  - `default`：ID 为 253，通常用于某些特定的默认路由。
  - `all`：表示操作所有路由表（通常用于查询）。
- **数字 ID**：路由表的 ID 是一个从 1 到 2^32 - 1 的数字。用户可以自定义路由表 ID，用于特定的路由策略。某些 ID（如 0、253、254、255）是系统保留的，具有特殊含义。
- **自定义名称**：可以通过配置文件（如 `/usr/share/iproute2/rt_tables` 或 `/etc/iproute2/rt_tables`，后者优先级更高）定义路由表的名称，方便用户使用有意义的字符串代替数字 ID。



如果在 `ip route` 命令中没有指定 `[ table TABLE_ID ]` 参数，系统会默认将路由添加到 `main` 表（ID 254）。但是对于某些特殊类型的路由（如 `local`、`broadcast` 和 `nat`），系统会默认将它们放入 `local` 表（ID 255）。



示例：

```
ip route add default            via 192.168.100.254
```

```
ip route add default table main via 192.168.100.254
```

```
ip route add default table 254  via 192.168.100.254
```

```
ip rouet show
```

```
ip route show table main
```

```
ip route show table local
```

```
ip route show table all
```



### proto

`[ proto RTPROTO ]` 参数（可选参数），它的具体作用是标识路由条目的来源或类型，即表明这条路由是由哪个协议或机制添加的。例如是静态配置的、由内核自动添加的，还是由动态路由协议（如 OSPF、BGP）生成的。

如果在 `ip route` 命令中没有指定 `[ proto RTPROTO ]` 参数，系统会默认将协议设置为 `boot`。

```
RTPROTO := [ kernel | boot | static | NUMBER ]
```



`RTPROTO` 可以是以下几种形式：

- 预定义的协议名称：
  - `kernel`：表示路由是由内核自动添加的，通常是在接口配置或自动配置过程中由内核生成的（如 IPv6 自动配置）。
  - `boot`：表示路由是在系统启动过程中添加的，通常由初始化脚本或系统配置添加。例如通过配置文件（如 `/etc/network/interfaces` 或 NetworkManager 配置）在系统启动时自动设置的路由。
  - `static`：表示路由是由管理员手动添加的，用于覆盖动态路由。路由守护进程通常会尊重这些路由，并可能将其通告给对等方。
- **数字 ID**：协议标识符可以用数字表示，范围是从 1 到 255 的整数。某些数字有固定含义（如 `kernel`、`boot`、`static`），而其他数字可以由管理员自由分配，用于标识自定义协议或来源。
- **自定义名称**：可以通过配置文件（如 `/usr/share/iproute2/rt_protos` 或 `/etc/iproute2/rt_protos`，后者优先级更高）定义协议的名称，方便用户使用有意义的字符串代替数字 ID。



文件 **/etc/iproute2/rt_protos** 内容：

```
#
# Reserved protocols.
#
0	unspec
1	redirect
2	kernel
3	boot
4	static
8	gated
9	ra
10	mrt
11	zebra
12	bird
13	dnrouted
14	xorp
15	ntk
16	dhcp
18	keepalived
42	babel
186	bgp
187	isis
188	ospf
189	rip
192	eigrp
```



`proto` 参数主要是对路由进行标记，标记这条路由的来源或由谁添加。但这种标记不是 100% 准确的，例如你可以手动添加一条静态路由，却标记为 kernel 添加的。

```
[root@localhost ~]# ip route add default via 192.168.100.254 proto kernel 
```

```
[root@localhost ~]# ip route show 
default via 192.168.100.254 dev ens160 proto kernel 
```



如果 proto 类型为 boot，在使用 ip route show 输出时，默认不显示

```
[root@localhost ~]# ip route add default via 192.168.100.254 proto boot 
```

```
[root@localhost ~]# ip route show 
default via 192.168.100.254 dev ens160 
```



示例：

```
ip route add default via 192.168.100.254
```

```
ip route add default via 192.168.100.254 proto boot
```

```
ip route add default via 192.168.100.254 proto static
```

```
ip route add default via 192.168.100.254 proto kernel
```



### scope

`[ scope SCOPE ]` 在 ip route 命令中，scope 是路由条目的一个属性，scope 决定了数据包如何被处理和发送。

```
SCOPE := [ host | link | global | NUMBER ]
```



**scope** 的可能值包括：

- **host**：数据包不会离开主机，通过本地回环接口（如 lo）或本地接口处理。
- **link**：数据包通过指定的本地接口（如 eth0）直接发送到目标地址，无需网关。内核会执行 ARP（IPv4）或邻居发现（IPv6）来查找目标的 MAC 地址，然后直接发送。
- **global**：数据包可能通过网关（via 参数指定）转发，涉及更复杂的发送流程，如通过网关的 ARP 查找、IP 转发等。
- **NUMBER**：自定义数值（通过 /etc/iproute2/rt_scopes 或 /usr/share/iproute2/rt_scopes 定义）。



如果未显式指定 scope，ip route 会根据路由类型和上下文推断合适的 scope。



示例：

```
ip route add 192.168.100.0/24 dev ens32 scope link
```

```
ip route add 192.168.100.0/24 dev ens32 via 192.168.100.254 scope global
```



### metric

`[ metric METRIC ]` 是一个可选参数。**METRIC** 是 32 位无符号整数（**0 到 4294967295** ），通常用于表示路由的优先级。当内核需要从多个路由条目中选择一条路由来转发数据包时，**metric 值较低的路由通常会被优先选择**。



默认值：如果未显式指定 metric，内核可能会根据路由类型或设备属性分配一个默认值。



在 ip route 命令中，metric 和 preference 是同义词，效果相同。



示例：

```
ip route add default via 192.168.100.254 metric 100
```

```
ip route add default via 192.168.100.254 preference 100
```



### ttl-propagate

`[ ttl-propagate { enabled | disabled } ]` 是一个可选参数，用于控制在**路由转发过程中是否继承或传播（propagate）数据包的 TTL**（Time To Live，生存时间）值。

TTL 是 IP 数据包头部的一个字段，用于限制数据包在网络中的生存时间，防止数据包无限循环转发。**每经过一个路由器，TTL 值通常会减 1，当 TTL 减到 0 时，数据包会被丢弃。**





`ttl-propagate` 参数有两个可选值：`enabled` 和 `disabled`（**默认值：enabled**）：

- **enabled**：在数据包转发时，保留原始数据包的 TTL 值（减 1 后）传递到下一跳，而不是重置 TTL 为系统默认值。
- **disabled**：在数据包转发时，不继承原始数据包的 TTL 值，而是重置 TTL 为系统默认值（通常是 64 或 128）。



**net.ipv4.ip_default_ttl**：设置系统默认的 TTL 值，默认为 64。



示例：

```
ip route add 192.168.100.0/24 via 192.168.100.254 dev ens32
```

```
ip route add 192.168.100.0/24 via 192.168.100.254 dev ens32 ttl-propagate enable
```

```
ip route add 192.168.100.0/24 via 192.168.100.254 dev ens32 ttl-propagate disable
```



## INFO_SPEC

**[ INFO_SPEC ]** 是可选参数，主要用于指定到达目标的路径（**via**、**dev**）和相关优化参数（**mtu** 等）。

```
INFO_SPEC := { NH | nhid ID } OPTIONS FLAGS [ nexthop NH ]...
```



### NH

**NH** 直接指定下一跳的详细信息，包括封装属性、下一跳地址、输出设备等。

```
NH := [ encap ENCAPTYPE ENCAPHDR ] [ via [ FAMILY ] ADDRESS ] [ dev STRING ] [ weight NUMBER ] NHFLAGS
```

- **encap ENCAPTYPE ENCAPHDR**：指定封装类型和相关属性。
- **via [ FAMILY ] ADDRESS**：指定下一跳的地址。
- **dev STRING**：指定输出设备（接口名称，如 eth0）。
- **weight NUMBER**：在多路径路由中指定该下一跳的权重，用于负载均衡。**仅在多路径下可以使用。**
- **NHFLAGS**：附加标志，如 onlink（假定下一跳直接连接）或 pervasive。



#### encap

**encap** 用于为路由指定**数据包的封装方式**，即在数据包外添加特定的协议头部。以实现隧道传输、流量工程或策略路由等功能。

```
[ encap ENCAPTYPE ENCAPHDR ]
```



**ENCAPTYPE**：指定封装类型，支持以下选项：

- **mpls**：多协议标签交换（MPLS）封装。
- **ip**：IP 隧道封装（如 GRE、VXLAN、Geneve）。
- **ip6**：IPv6 隧道封装（未在提供的文档中明确列出，但通常指 IP6-in-IP6 隧道）。
- **seg6**：IPv6 段路由（Segment Routing IPv6, SRv6）封装。
- **seg6local**：本地 SRv6 段处理。
- **rpl**：**RPL（IPv6 Routing Protocol for Low-Power and Lossy Networks）**封装（未在文档中详细描述，可能为特定场景支持）。



**ENCAPHDR**：封装头部的具体属性，根据 **ENCAPTYPE** 的不同而变化：

- **MPLSLABEL**：用于 MPLS 封装，格式为 **[ LABEL ] [ ttl TTL ]**。
- **SEG6HDR**：用于 SRv6 封装，格式为 [ mode SEGMODE ] segs ADDR1,ADDRi,ADDRn [hmac HMACKEYID] [cleanup]。



#### via

参数格式：`[ via [ FAMILY ] ADDRESS ]`

FAMILY 指定**下一跳地址的协议类型**，确保内核正确解析和处理 ADDRESS。如果未指定 FAMILY，内核会根据上下文（如 ADDRESS、路由的目标地址和接口类型等）推断。

```
FAMILY := [ inet | inet6 | mpls | bridge | link ]
```



如果 ADDRESS 为 ipv4 格式（`192.168.100.254`），则 FAMILY 推断为 **inet**；

```
ip route add 192.168.100.0/24 via [ inet ] 192.168.100.254
```



如果 ADDRESS 为 MAC 格式（`00:11:22:33:44:55`），则推断为 **link**。

```
ip route add 192.168.100.0/24 via [ link ] 00:11:22:33:44:55
```



在配置路由表时，下一跳地址一般配置为 IP 地址。在进行路由转发时，先通过 ARP 将 IP 地址解析成 MAC 地址，然后将数据包的**目标 MAC 地址**设置为**解析得到的 MAC 地址** ，将数据包转发至下一跳节点。

当然，也可以直接将下一跳地址设置为设备接口的 **MAC 地址**，从而省略 ARP 解析的过程，但这种方式在实际应用中基本不常使用。



#### dev

指定输出设备（接口名称，如 eth0）。



#### weight

在多路径路由中指定该下一跳的权重，用于负载均衡。**仅在多路径下可以使用。请查看 nexthop 字段。**



#### NHFLAGS

**注意：以下内容为 AI 阐述，我实测存在问题**



NHFLAGS 是下一跳的附加标志，用于修改下一跳的行为或假设，影响数据包的转发逻辑。

参数格式：`NHFLAGS := [ onlink | pervasive ]`



**onlink**

告诉内核忽略下一跳地址的子网检查。假定**下一跳（nexthop）**，即数据包将要发送到的下一个地址，是直接连接到当前网络接口（link）的，即下一跳地址的接口与当前网络接口属于同一个**广播域**。

如果指定了 onlink 参数，则**下一跳地址**必须不处于**当前接口网段**，并且需要通过 dev 参数指定输出设备，否则将会报错。



**pervasive**

如果为 pervasive 参数，则**下一跳地址**必须**处于当前接口网段**内，否则将会报错，默认选项。



示例：



ens160 网卡 IP 地址为 **192.168.100.100**



下一跳地址**在接口网段内**，默认为 pervasive 模式。

```
ip route add 192.168.200.0/24 via 192.168.100.254 dev ens160
```



下一跳地址**在接口网段内**，默认为 pervasive 模式，且不能指定 onlink 参数，否则会报错。

```
ip route add 192.168.150.0/24 via 192.168.100.254 dev ens160 onlink

Error: Nexthop has invalid gateway.
```



下一条地址**不在接口网段内**，需要手动添加 onlink 参数，否则会报错。

```
ip route add 192.168.150.0/24 via 192.168.200.254 dev veth1 

Error: Nexthop has invalid gateway.
```

```
ip route add 192.168.150.0/24 via 192.168.200.254 dev veth1 onlink
```





### nhid ID

nhid ID 使用一个唯一的整数 ID 引用一个预定义的**下一跳对象**，下一跳对象通常通过 ip nexthop 命令预先创建，包含下一跳的地址、设备、封装等信息。

提供了一种**可重用**的下一跳配置方式，将下一跳信息抽象为对象，减少重复配置，提高配置效率和一致性。

修改下一跳对象（通过 ID）会**自动影响所有引用该 ID 的路由**，而无需逐一修改路由条目。



使用 ip nexthop 命令创建下一跳对象：

```
ip nexthop add id 10 via 192.168.100.254 dev ens32
```



在 ip route add 中使用 nhid：

```
ip route add 192.168.100.0/24 nhid 10
```



### nexthop

对于同一个目标地址网段，可以通过 nexthop 指定多个下一跳地址，并详细配置下一跳的相关信息，从而实现**负载均衡**的效果。



`{ NH | nhid ID }` 与 `[ nexthop NH ]...` 是互相冲突的：

- 如果使用 `{ NH | nhid ID }` 则只能指定一个下一跳地址，且不能使用 **weight** 参数。
- 如果要指定多个下一条地址，则必须使用 `[ nexthop NH ]...` 进行指定。

```
INFO_SPEC := { NH | nhid ID } OPTIONS FLAGS [ nexthop NH ]...
```

```
NH := [ encap ENCAPTYPE ENCAPHDR ] [ via [ FAMILY ] ADDRESS ]
	    [ dev STRING ] [ weight NUMBER ] NHFLAGS
```



使用 `{ NH | nhid ID }` 指定一个下一条地址（**使用 weight 参数会导致错误**）

```
ip route add 192.168.100.0/24 via 192.168.100.1 dev ens160
```

```
ip route add 192.168.100.0/24 via 192.168.100.1 dev ens160 weight 1

Error: either "to" is duplicate, or "weight" is a garbage.
```



使用 `[ nexthop NH ]...`  指定多个下一条地址（**混合使用会导致错误**）

```
ip route add 192.168.100.0/24 \
 	nexthop via 192.168.100.1 dev ens160 weight 8 \
 	nexthop via 192.168.100.2 dev ens160          \   # 不指定 weight 参数默认值为 1
 	nexthop via 192.168.100.3 dev ens160 weight 1
```

```
ip route add 192.168.100.0/24 \
 	        via 192.168.100.1 dev ens160 weight 8 \   # 没有添加 nexthop 则是 { NH | nhid ID }
    nexthop via 192.168.100.2 dev ens160 weight   \   # 添加了 nexthop 则是 [ nexthop NH ]...
 	nexthop via 192.168.100.3 dev ens160 weight 1
 	
Error: either "to" is duplicate, or "weight" is a garbage.
```

```
ip route add 192.168.100.0/24 \
 	        via 192.168.100.1 dev ens160          \   # 没有添加 nexthop 则是 { NH | nhid ID }
    nexthop via 192.168.100.2 dev ens160 weight   \   # 添加了 nexthop 则是 [ nexthop NH ]...
 	nexthop via 192.168.100.3 dev ens160 weight 1
 	
Error: Nexthop gateway does not match RTA_GATEWAY.
```



#### weight

在 Linux 的 `iproute2` 工具中，`weight` 参数以 8 位无符号整数（unsigned 8-bit integer）存储，范围为 **1 - 255**。

如果尝试设置超出这个范围的值，可能会被截断到有效范围，或者命令会报错，具体行为取决于内核版本和 `iproute2` 的实现。



权重（weight）用于在多路径路由（multipath routing）中确定流量的分配比例。例如，假设有两条下一跳路径（路径A和路径B），你可以设置 **25%** 的流量通过路径 A 转发，而 **75%** 的流量通过路径 B 转发。



**两个下一跳，权重为 1 和 3**：

- 总权重 = 1 + 3 = 4
- 第一个下一跳的流量比例 1 / 4 = 25%
- 第二个下一跳的流量比例 3 / 4 = 75%

```
ip route add 192.168.100.0/24 \
    nexthop via 192.168.100.1 dev ens160 weight 1 \
    nexthop via 192.168.100.2 dev ens160 weight 3
```

```
ip route show

192.168.100.0/24 
	nexthop via 192.168.100.1 dev ens160 weight 1 
	nexthop via 192.168.100.2 dev ens160 weight 3 
```



**三个下一跳，权重为 2, 3, 5**：

- 总权重 = 2 + 3 + 5 = 10
- 第一个下一跳的比例 2 / 10 = 20%
- 第二个下一跳的比例 3 / 10 = 30%
- 第三个下一跳的比例 5 / 10 = 50%

```
ip route add 192.168.100.0/24 \
    nexthop via 192.168.100.1 dev ens160 weight 2 \
    nexthop via 192.168.100.2 dev ens160 weight 3 \
    nexthop via 192.168.100.3 dev ens160 weight 5
```

```
ip route show

192.168.100.0/24 
	nexthop via 192.168.100.1 dev ens160 weight 2 
	nexthop via 192.168.100.2 dev ens160 weight 3 
	nexthop via 192.168.100.3 dev ens160 weight 5
```



### OPTIONS

```
OPTIONS := FLAGS [ mtu NUMBER ] [ advmss NUMBER ] [ as [ to ] ADDRESS ]
           [ rtt TIME ] [ rttvar TIME ] [ reordering NUMBER ]
           [ window NUMBER ] [ cwnd NUMBER ] [ initcwnd NUMBER ]
           [ ssthresh NUMBER ] [ realms REALM ] [ src ADDRESS ]
           [ rto_min TIME ] [ hoplimit NUMBER ] [ initrwnd NUMBER ]
           [ features FEATURES ] [ quickack BOOL ] [ congctl NAME ]
           [ pref PREF ] [ expires TIME ] [ fastopen_no_cookie BOOL ]
```



#### mtu

MTU（Maximum Transmission Unit）是指网络层（即 IP 层）能够传输的最大数据包大小。这个大小包括 IP 头部以及有效载荷（payload），但不包括数据链路层（如以太网）的头部或尾部（如以太网帧的 14 字节头部和 4 字节的 FCS 校验）。



mtu 的具体参数设置为 `[ mtu NUMBER ]` 或 `[ mtu lock NUMBER ]`。

如果没有指定 lock ，则会启用路径 MTU 发现机制，MTU 值可能会被内核动态更新；如果指定 lock 则 MTU 值完全固定。



ipv4 数据包进行路由时，**IP 数据包的大小超过路由条目中设置的 MTU 值**。

- 如果**未设置 DF 标志（允许分片）**，内核会将数据包分片成符合 MTU 大小的小数据包，然后通过这条路由发送。
- 如果**设置了 DF 标志（不允许分片）**，内核不会分片数据包，而是直接丢弃该数据包。



IPv6 情况下，IP 数据包的大小超过路由条目中设置的 MTU 值。只有在**源端和目的端**会进行 IP 分片，中途路由器会直接丢弃数据包。



示例：

```
ip route add 192.168.100.0/24 via 192.168.100.254 dev ens160 mtu 1500
```

```
ip route add 192.168.100.0/24 via 192.168.100.254 dev ens160 mtu lock 1500
```



#### advmss

MSS（Maximum Segment Size，最大分段大小）是指 TCP 报文段中数据部分（即有效载荷）的最大字节数，不包括 TCP 头部和 IP 头部。MSS 是在 TCP 连接建立时（通过三次握手过程中的 SYN 包）由通信双方协商确定的，通常基于路径上最小 MTU（Maximum Transmission Unit，最大传输单元）计算得出。



MSS = MTU - (IP 头部长度 + TCP 头部长度)

标准 IPv4 头部长度为 20 字节，TCP 头部长度也为 20 字节（不考虑选项字段），所以对于 MTU 为 1500 字节的以太网，MSS 通常是 1460 字节。

如果有额外的头部选项（如 TCP 选项或 IP 选项），MSS 会相应减小。



MSS 是 TCP 层面的概念，用于限制 TCP 报文段中数据部分的长度，以确保生成的 IP 数据包不会超过路径上的 MTU，从而避免 IP 层分片。



advmss 参数格式为：`[ advmss NUMBER ]`



示例：

```
ip route add 192.168.100.0/24 via 192.168.100.254 dev ens160 advmss 1460
```



#### RTO

RTO（Retransmission Timeout）是 TCP 中的重传超时时间，它是指 TCP 协议在发送数据包后，如果在一定时间内（RTO 值）没有收到对方的确认（ACK），就会认为数据包可能丢失或被延迟，从而触发重传机制。



RTO 计算通常基于 RTT 和 RTT 方差，公式大致如下：

```
RTO = RTT + k * RTT_variance
```

- 其中 `k` 是一个常数（通常为 4），用来提供容错空间。
- `RTT` 和 `RTT_variance` 的默认值不是固定的，在数据传输中，会根据网络的实际情况动态调整。



RTT（Round Trip Time，往返时间）是数据包从发送到接收到响应**所需的时间估计值**。RTT 被用来 RTO。



**RTT** 参数格式：`[ rtt TIME ]`

**RTT_variance** 参数格式：`[ rttvar TIME]`



通过 `ip route add` 设置的 `rtt` 和 `rttvar` 参数并不是固定不变的，它们只是**初始值**。在实际通信过程中，这些值会根据网络的实际情况动态调整。



如果在指定 `TIME` 时没有附加单位后缀，值将被视为原始值，直接传递给路由代码，以保持与早期版本的兼容性。

如果需要明确指定单位，可以使用后缀：

- `s`, `sec`, 或 `secs` 表示秒。
- `ms`, `msec`, 或 `msecs` 表示毫秒。



示例：

```
ip route add 10.0.0.0/24 via 192.168.1.1 dev eth0 rtt 50ms rttvar 10ms
```





#### rto_min 

rto_min 用于设置与目标地址通信时所使用的最小 TCP 重传超时时间（Retransmission TimeOut, RTO）。



如果在指定 `TIME` 时没有附加单位后缀，值将被视为原始值，直接传递给路由代码，以保持与早期版本的兼容性。

如果需要明确指定单位，可以使用后缀：

- `s`, `sec`, 或 `secs` 表示秒。
- `ms`, `msec`, 或 `msecs` 表示毫秒。



示例：

```
ip route add 10.1.1.0/24 via 192.168.1.1 dev eth0 rto_min 300ms
```





#### reordering

数据包重排序（reordering）是指网络中数据包由于路径不同、延迟差异或网络拥塞等原因到达目的地的顺序与发送顺序不一致的现象。TCP 协议会对接收到的数据包进行重新排序以确保数据的正确性，但过多的重排序可能会导致性能下降，因为 TCP 可能会误认为数据包丢失而触发不必要的重传。



reordering 参数格式：`[ reordering NUMBER ]`

通过 `reordering NUMBER` 选项，用户可以指定到某个目的地的路径上允许的最大重排序数量。这个值定义了 TCP 在该路径上能够容忍的数据包乱序程度。如果未设置该选项，Linux 系统会使用通过 sysctl 变量 `net/ipv4/tcp_reordering` 定义的默认值。



示例：

```
ip route add 10.0.0.0/24 via 192.168.1.1 dev eth0 reordering 5
```



#### window

TCP 使用滑动窗口机制来控制数据发送的速率。window NUMBER 定义了接收端（即本地主机）愿意接受的最大数据量。通过设置这个值，可以限制对端一次性发送的数据量，避免本地主机因处理能力不足而出现缓冲区溢出或性能下降的情况。



window 参数示例：`[ windows NUMBER]`

TCP 连接设置最大窗口大小为 16384 字节。如果不设置，Linux 将使用默认的 TCP 窗口大小，通常由内核参数（如 `net.ipv4.tcp_rmem` 和 `net.ipv4.tcp_wmem`）或应用程序控制。



示例：

```
ip route add 10.0.0.0/24 via 192.168.1.1 dev eth0 window 16384
```



#### cwnd

拥塞窗口（cwnd）是 TCP 中发送方维护的一个的状态变量，它限制在未收到接收方确认（ACK）的情况下，发送方一次可以发送的最大数据量。



cwnd 参数：`[ cwnd NUMBER]`

`cwnd NUMBER` 设置了一个固定的拥塞窗口上限值，单位是数据段（通常与 MSS，即最大段大小相关）。



如果不使用 `lock` 标志，`cwnd` 值只是一个建议值，内核可能会根据实际网络条件（如拥塞控制算法）调整窗口大小。如果使用了 `lock`，则强制执行指定的 `cwnd` 值，无法更改。



示例：

```
ip route add 10.0.0.0/24 via 192.168.1.1 dev eth0 cwnd 10
```

```
ip route add 10.0.0.0/24 via 192.168.1.1 dev eth0 cwnd lock 10
```





#### quickack

TCP 连接的快速确认模式（Quick ACK mode）是 TCP 栈会尽量快速地发送确认（ACK）数据包，而不是等待一段时间以便将确认与其他数据一起发送（即延迟确认，Delayed ACK）。

当设置为禁用时，TCP 栈会使用标准的延迟确认机制，即在一定时间内（通常是 40ms）等待是否有更多数据可以一起发送确认。



**quickack** 参数示例：`[ quickack BOOL ]`

在 ip route 中 BOOL 为 0（false）或 1（true），不可用 false 或 true 代替，quickack 默认为关闭（0）。



示例：

```
ip route add 192.168.100.0/24 via 192.168.100.254 dev ens160 onlink quickack 1
```



#### congctl

`congctl NAME` 选项是 `ip route` 命令中用于设置特定目标地址的 TCP 拥塞控制算法的一个参数。它允许管理员为特定的路由路径指定一个 TCP 拥塞控制算法，而不是依赖系统全局默认的拥塞控制算法或应用程序设置的算法。



congctl 参数：`[ congctl [ lock ] NAME ]`

在默认情况下，如果不设置 `congctl`，Linux 会使用系统全局的默认拥塞控制算法（通常通过 `sysctl net.ipv4.tcp_congestion_control` 设置），或者由应用程序自行指定。

如果使用了 `congctl lock NAME` 的形式，指定的拥塞控制算法将被强制应用，应用程序无法覆盖该设置。



指定的 `NAME` 必须是系统中已加载或支持的拥塞控制算法，可以通过查看 `/proc/sys/net/ipv4/tcp_available_congestion_control` 来确认可用算法。



示例：

```
ip route add 192.168.1.0/24 via 192.168.1.1 dev eth0 congctl cubic
```

```
ip route add 192.168.1.0/24 via 192.168.1.1 dev eth0 congctl lock cubic
```



#### fastopen_no_cookie

TCP Fast Open 是一种优化 TCP 连接建立过程的机制，旨在减少连接建立时的延迟。传统 TCP 连接需要三次握手（SYN, SYN-ACK, ACK）才能完成，而 TFO 允许客户端在初始 SYN 包（第一次握手）中携带数据，并让服务器在 SYN-ACK 包中返回响应数据，从而减少了额外的往返时间 (RTT)。为了实现这一功能，TFO 通常依赖于一个“cookie”机制，该 cookie 由服务器生成并发送给客户端，用于验证客户端的身份，防止伪造请求和攻击。

`fastopen_no_cookie` 选项允许在特定路由上启用 TCP Fast Open，但不要求使用 cookie 进行验证。



fastopen_no_cookie 参数示例：`[ fastopen_no_cookie BOOL ]`



示例：

```
ip route add 192.168.1.0/24 dev eth0 fastopen_no_cookie 1
```



#### expires

通过设置 `expires TIME`，管理员可以创建一个只在特定时间内有效的路由条目。时间到期后，内核会自动删除该路由，无需手动干预。这对于需要在特定时间段内临时调整网络流量的场景非常有用，例如临时重定向流量或测试网络配置。



expires 参数示例：`[ expires TIME ]`

`TIME` 参数可以指定为一个时间间隔，通常以秒为单位（具体单位取决于内核实现）。

**仅 IPv6 支持**，如果尝试在 IPv4 路由上使用 `expires` 选项，命令会失败或被忽略。



示例：

```
ip -6 route add 2001:db8:1::/64 via 2001:db8:2::1 dev eth0 expires 3600
```



#### pref 

`pref PREF` 允许管理员为特定的 IPv6 路由设置优先级，从而影响路由选择的过程。优先级值会影响路由的偏好程度，值越高，路由被选中的可能性越大。



以下是 `pref PREF` 的三个可选值及其含义：

- **low**：表示该路由的优先级最低。
- **medium**：表示该路由具有默认优先级。
- **high**：表示该路由的优先级最高。



`pref PREF` 选项仅适用于 IPv6 路由，IPv4 路由不直接支持此选项。该选项与路由的 `metric` 或 `preference` 值不同，`pref` 是专门为 IPv6 路由优先级设计的，基于 RFC 4191 的标准。



**pref** 参数示例：`pref PREF`



示例：

```
ip -6 route add 2001:db8:1::/64 via 2001:db8:2::1 dev eth0 pref high
```



