# Rule

**ip rule** 用于操作**路由策略数据库中的规则**，**Linux 内核**根据这些规则来执行路由选择。

互联网中使用的经典路由算法主要**基于数据包的目的地址**（按照最长匹配规则排序，理论上包括 TOS 字段，但实际很少使用）来决定路由路径。

RPDB 不仅依据目的地址，还能根据数据包的其他字段（如源地址、IP 协议、传输协议端口，甚至有效载荷）来实现差异化路由，这种方式被称为**策略路由**。



RPDB 通过一组规则（rules）来选择路由路径，每条规则包含两部分：

- **选择器（Selector）**：用于匹配数据包的条件，比如源地址、目的地址、输入接口、TOS 值、防火墙标记（fwmark）等。
- **动作（Action）**：如果选择器匹配成功，将执行相应动作。动作可能指向路由表，若在路由表中找到匹配的路由路径，则返回该路径；若未找到，则不返回结果。动作也可能直接指示失败（如丢弃或生成错误）。当返回路由路径或明确指示失败时，**RPDB 的查找过程将终止**；若未返回路径，则继续检查下一条规则。

规则按照优先级（Priority）顺序扫描，**优先级数值越小，优先级越高**。也就是说，优先级为 0 的规则会最先被检查。



通常情况下，动作的结果是选择下一跳（nexthop）和输出设备（output device）。



在系统启动时，内核会配置一个默认的 RPDB，包含以下三条规则：

1. **优先级 0**：匹配所有数据包，动作是查找 `local` 路由表（ID 255）。`local` 表是一个特殊路由表，包含本地地址和广播地址的高优先级控制路由。
2. **优先级 32766**：匹配所有数据包，动作是查找 `main` 路由表（ID 254）。`main` 表是普通的路由表，包含所有非策略路由。管理员可以删除或覆盖这条规则。
3. **优先级 32767**：匹配所有数据包，动作是查找 `default` 路由表（ID 253）。`default` 表默认是空的，用于在前面规则未匹配时进行后处理。这条规则也可以被删除。



RPDB 中的规则可以执行不同的动作类型，包括：

- **unicast**：返回规则引用的路由表中找到的路由。
- **blackhole**：默默丢弃数据包（不返回任何错误）。
- **unreachable**：生成“网络不可达”（Network is unreachable）的错误。
- **prohibit**：生成“通信被管理员禁止”（Communication is administratively prohibited）的错误。
- **nat**：将 IP 数据包的源地址转换为其他值（即进行地址转换）。



每个 RPDB 条目都有额外的属性。例如，每个规则都有一个指向某个路由表的指针。NAT 和伪装规则有一个属性，用于选择要翻译/伪装的新 IP 地址。此外，规则还具有一些可选属性，这些属性与路由相同，即 realms。这些值不会覆盖路由表中包含的值。它们仅在路由未选择任何属性时使用。



## 语法

```
ip [ OPTIONS ] rule { COMMAND | help }

ip rule [ show [ SELECTOR ]]

ip rule { add | del } SELECTOR ACTION

ip rule { flush | save | restore }

SELECTOR := [ not ] [ from PREFIX ] [ to PREFIX ] [ tos TOS ]
       [ fwmark FWMARK[/MASK] ] [ iif STRING ] [ oif STRING ]
       [ priority PREFERENCE ] [ l3mdev ] [ uidrange NUMBER-NUMBER]
       [ ipproto PROTOCOL ] [ sport [ NUMBER | NUMBER-NUMBER ] ]
       [ dport [ NUMBER | NUMBER-NUMBER ] ] [ tun_id TUN_ID ]

ACTION := [ table TABLE_ID ] [ protocol PROTO ] [ nat ADDRESS ] [
       realms [SRCREALM/]DSTREALM ] [ goto NUMBER ] SUPPRESSOR

SUPPRESSOR := [ suppress_prefixlength NUMBER ] [ suppress_ifgroup
       GROUP ]

TABLE_ID := [ local | main | default | NUMBER ]
```



**ip rule add - 添加一条新规则**

**ip rule delete - 删除一条规则**

**type TYPE（默认）**

指定规则的类型。有效的类型列表已在前面小节中给出。



**from PREFIX**

匹配数据包的源地址前缀。



**to PREFIX**

匹配数据包的目的地址前缀。



**iif NAME**

匹配数据包的入接口（incoming interface）。

指定规则只对从特定网络接口进入的数据包生效。如果接口是 `lo`（loopback），则规则只匹配从本地主机发起的数据包。这可以用于区分转发流量和本地流量，从而为它们分配不同的路由表。



**oif NAME**

匹配数据包的出接口（outgoing interface）。

指定规则只对**从特定网络接口发出的数据包**生效，只有当数据包确定要从指定接口发送时，这条规则才会应用。

`oif` 参数并不是针对所有数据包，而是仅限于那些由本地主机发起的数据包，并且这些**数据包在发送时已经明确绑定到一个特定的网络接口**。



**tos TOS 或 dsfield TOS**

匹配数据包的服务类型（Type of Service, TOS）值。



**fwmark MARK**

匹配数据包的防火墙标记（firewall mark）。



**uidrange NUMBER-NUMBER**

匹配数据包发起者的用户 ID（UID）范围。

此参数用于**匹配由特定用户或用户范围发起的数据包**，通常用于本地流量。



**ipproto PROTOCOL**

匹配数据包的 IP 协议类型。

指定规则只对特定协议（如 TCP、UDP、ICMP 等）的数据包生效。协议可以是名称或数字（如 6 表示 TCP）。



**sport NUMBER | NUMBER-NUMBER**

匹配数据包的源端口或端口范围。



**dport NUMBER | NUMBER-NUMBER**

匹配数据包的目的端口或端口范围。



**priority PREFERENCE**
指定规则的优先级。PREFERENCE 是一个无符号整数值，数值越大优先级越低，规则按数值递增的顺序处理。每条规则应明确设置一个唯一的优先级值。选项 `preference` 和 `order` 是 `priority` 的同义词。



**table TABLEID**

指定规则匹配后查找的**路由表 ID**。

如果数据包匹配规则，则使用指定的路由表进行路由决策。可以使用 **/etc/iproute2/rt_tables** 文件中定义的**字符串与数字的映射关系**来代替**路由表 ID**。如 `table local` 替代 `table 255` 。





**protocol PROTO**

标识规则是由哪个路由协议（如 Zebra）添加的。例如，Zebra 安装的规则会标记为 `RTPROT_ZEBRA`。此参数在 `flush` 和 `save` 命令中用于筛选规则。



**suppress_prefixlength NUMBER**

拒绝前缀长度小于等于指定值的路由决策。

用于限制路由表中某些路由的使用，只有前缀长度大于指定值的路由才会被接受。



**suppress_ifgroup GROUP**

拒绝使用属于指定接口组的设备的路由决策。

如果路由决策涉及的设备属于指定的接口组，则拒绝该路由。



**realms FROM/TO**

如果规则匹配且路由表查找成功，则选择领域（realm）。



`realms` 可以理解为一种标签或标识符，用于将路由或流量分组到不同的“领域”中，以便后续进行更精细的控制或管理。

- **FROM 领域**：表示数据包的来源领域，通常与数据包的源地址或入接口相关联。

- **TO 领域**：表示数据包的目标领域，通常与数据包的目的地址或出接口相关联。



当一条规则匹配成功（即数据包满足规则的条件，如源地址、目的地址等），并且路由表查找也成功（即找到了一条有效的路由）时，系统会将数据包分配到指定的 `FROM` 和/或 `TO` 领域。

如果路由查找过程中没有选择任何目标领域（即路由表中没有指定 `TO` 领域），则使用规则中指定的 `TO` 领域作为默认目标领域。



**nat ADDRESS**

指定源地址 NAT（网络地址转换）的地址块基地址。
