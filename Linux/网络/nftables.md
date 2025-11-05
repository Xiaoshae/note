# nftables

`nftables` 是一个现代的、功能强大的 Linux 内核数据包过滤框架，旨在**完全取代** 传统（legacy）的 `iptables`、`ip6tables`、`arptables` 和 `ebtables` 工具。

它从 Linux 内核 3.13 版本（2014年）开始引入，从 **2019 年左右**开始成为所有主流 Linux 发行版（如 Debian 10+、RHEL 8+、Ubuntu 20.04+）的**默认防火墙后端**。



**iptables** 的首次推出可以追溯到 **Linux 内核 2.4.x 系列**。这个系列的内核在 **2001 年**左右发布。

**iptables** 是用于 IPv4 流量的，而 **ip6tables** 用于 IPv6 流量，**arptables** 用于 ARP 流量，**ebtables** 用于以太网帧。它们共同取代了更早期的 **ipchains** 和 **ipfwadm** 工具，并在此后很长一段时间内成为 Linux 防火墙的标准。



尽管 **iptables** 非常成熟和稳定，但随着现代网络需求的增长和 Linux 内核的发展，它逐渐暴露出一些局限性，这也是 **nftables** 等新工具出现的原因：

-  针对 IPv4 和 IPv6，需要分别使用 `iptables` 和 `ip6tables`，管理起来比较分散和繁琐。
- 它的命令行语法复杂且不够直观，尤其是处理复杂的规则集时，容易出错。
- 在大型、复杂的规则集中，`iptables` 的处理是线性的。每当数据包到达时，它必须从头到尾遍历整个规则集，这在规则数量巨大时会导致 **性能下降**。
- 替换或修改大型规则集时，需要先清除旧规则，再加载新规则。这期间存在一个短暂的窗口期，可能导致网络中断或安全漏洞，因为它缺乏原子的、整体性的规则集替换能力。

-  它主要依赖固定的表（如 `filter`、`nat`、`mangle`）和链（如 `INPUT`、`OUTPUT`、`FORWARD`）。用户如果需要更灵活的匹配或计数器，需要进行更复杂的配置。



`nftables` 引入了一套新的、更灵活的架构。理解它的核心组件（**表、链、规则**）至关重要。



## **表 (Table)**

NFTables 中的**表**是用于**组织和隔离不同类型网络流量处理规则的容器**。

一个表可以包含多条**链**，这些链里又包含了具体的过滤和操作规则。表的主要作用是将不同目的或不同协议的规则集分开，保持配置的整洁和模块化。

您可能有一个专门处理 IPv4 流量的表，一个专门处理 IPv6 流量的表，或者一个专门处理桥接（bridge）流量的表。



每个表都必须与一个**地址族（family）**关联，这决定了该表中的规则将应用于哪种类型的网络流量。常见的地址族包括：

- `ip`: 适用于 IPv4 流量。
- `ip6`: 适用于 IPv6 流量。
- `inet`: 适用于 IPv4 和 IPv6 **两者**（混合表）。
- `arp`: 适用于 ARP 流量。
- `bridge`: 适用于 Linux 网桥上的二层（L2）流量。



在 NFTables 中，**可以**创建多个相同地址族的表。

NFTables 规则的实际执行顺序，**不是由表（Table）决定的，而是由链（Chain）决定的**，具体来说是基础链（Base Chain）的：

1. **挂载点（Hook）**：数据包在网络堆栈中的位置（如 `input`、`forward` 等）。
2. **优先级（Priority）**：在同一个挂载点上，用于确定不同基础链执行顺序的数值。



**链的优先级（Chain Priority）**

当一个数据包到达内核中的某个**挂载点（Hook）时，Netfilter 框架会检查所有在此挂载点注册的基础链（Base Chain）**，并将它们按**优先级（Priority）值**从小到大的顺序依次执行。

- **优先级值越小，执行越早（优先级越高）。** 优先级可以为负值。



## **链 (Chain)**

链是包含一系列按顺序执行的**规则（Rule）**的容器。数据包在网络堆栈中流经特定位置时，会触发相应的链进行检查。



**链主要分为两大类：**

- **基本链 (Base Chain):** 这种链会附加到内核的网络钩子（Hooks）上，用于处理流经网络栈的数据包。这等同于 `iptables` 的内置链。
- **常规链 (Regular Chain):** 这种链不直接附加到钩子上，主要用于“跳转”（jump），类似于 `iptables` 的自定义链，用于组织和优化规则集。



### **hook (钩子)**

钩子定义**基本链**附加在内核的哪个位置。对于 `ip`/`ip6`/`inet` 族，主要有 5 个钩子：

- **prerouting**
- **input**
- **forward**
- **output**
- **postrouting**



### **type（类型）**

在 `nftables` 的 `inet` 簇（family）中，当你定义一个**基本链 (base chain)**（即挂载到内核钩子上的链）时，`type` 关键字可配置的选项**只有以下三个**：

- **filter**
- **nat**
- **rout**



在 nftables 中，**mangle、raw 或 security 这些类型**的功能**不再通过专门的链类型来实现**，而是通过将链挂载到**特定的钩子 (hook)**、设置**特定的优先级 (priority)** 以及使用**特定的表达式 (expressions)** 来完成的。



#### filter 类型

filter 是最常用也是**默认**的类型。如果你在定义基本链时不显式指定 `type`，它将默认为 `filter`。

它的主要作用是执行数据包的**过滤**操作，即决定数据包的最终命运：`accept` (接受)、`drop` (丢弃) 或 `reject` (拒绝)。 

**适用钩子 (Hook)**：

- **prerouting**
- **input**
- **forward**
- **output**
- **postrouting**



#### nat 类型

nat 类型**专门用于**执行网络地址转换 (NAT)。

它的主要用途是修改数据包的源地址或目标地址，具体是以下几个：

- **snat** (源地址转换)
- **dnat** (目标地址转换)
- **masquerade** (地址伪装，一种特殊的 SNAT)
- **redirect** (端口重定向，一种特殊的 DNAT)



**适用钩子 (Hook)**：

- **prerouting** (用于 `dnat` 和 `redirect`，在路由决策*之前*修改目标地址)
- **postrouting** (用于 `snat` 和 `masquerade`，在路由决策*之后*修改源地址)
- **output** (用于修改**本地产生**的数据包的目标地址或源地址)



**nat** 类型的链仅**对每个新连接的第一个数据包**执行规则评估。一旦连接被建立（并记录在连接跟踪系统中），后续属于同一连接的数据包将**自动**应用相同的 NAT 规则，而不会再次遍历此链。这极大地提高了性能。



#### route 类型

route 是一个相对特殊且不那么常用的类型，主要用于在路由决策前进行一些高级操作。

它的主要用途在数据包进行路由查询**之前**修改数据包的元数据，以影响路由决策（即策略路由）。

例如，根据数据包的特定属性（如用户 ID）为其设置 `fwmark`，然后配置策略路由，基于这个标记将其定向到不同的路由表。



**适用钩子 (Hook)**： `type route` **只能**用于 `output` 钩子。



此类型的链在 `output` 钩子上的执行优先级**高于** `type filter` 链。它允许你在数据包被本地路由子系统处理之前进行最后的修改。

```bash
# 添加一个 route 链，在 output 钩子上，优先级非常高
nft add chain inet my_router output { type route hook output priority -150 \; }

# 规则：如果数据包由 UID 为 1000 (www-data) 的进程产生，则设置一个防火墙标记
# 这个标记 '10' 稍后可以被 'ip rule' 用来选择不同的路由表
nft add rule inet my_router output skuid "www-data" meta mark set 10
```



### type 示例

#### mangle (修改数据包)

在 nftables 中修改数据包头（如 `TOS`/`DSCP`、`TTL`）或设置 `meta mark` (防火墙标记)。可以在**任何 type filter链中**执行这些操作。

- 要在**路由前**修改（相当于 `iptables` 的 `PREROUTING mangle`），你可以在 `prerouting` 钩子上创建一个 `type filter` 链。
- 要在**路由后**修改（相当于 `iptables` 的 `POSTROUTING mangle`），你可以在 `postrouting` 钩子上创建一个 `type filter` 链。



在 `prerouting` 钩子上设置标记：

```bash
nft add chain inet my_mangle prerouting { type filter hook prerouting priority -150 \; }
nft add rule inet my_mangle prerouting tcp dport 443 meta mark set 0x1
```



### **priority (优先级)**

在 **iptables** 时代，处理顺序是固定的（**raw** -> **mangle** -> **nat** -> **filter**）。



在 **nftables** 中，您可以在**同一个钩子（例如 prerouting）上挂载任意多个链（即使它们在不同的表中）**。

优先级（Priority）就是用来决定这些链在同一个钩子上的执行顺序的。**优先级是一个整数，数字越小，优先级越高，越先执行。**



Netfilter 定义了一套**推荐优先级**，用来确保数据包以一种合乎逻辑的顺序被处理。

为了确保用于 **mark(标记功能)** 的**基础链（自定义链名为 mangle）**可以和用于 **filter(过滤功能)** 的**基础链（名为 filter）**可以协同工作，必须保证 **mangle 链的优先级必须高于 filter 链**。



假设一个场景：给所有来自 1.1.1.1 的包打上一个**标记** (mark)，**然后**丢弃 (drop) 所有带这个标记的包。

1. **mangle(标记功能)**，你需要先执行“打标记”的动作。
2. **filter(过滤)** 你才能根据这个标记去执行“丢弃”的动作。

如果 **filter(过滤功能)** 在 **mangle(标记功能)** 之前执行，那么当 `filter` 检查时，标记（mark）还不存在，规则就失效了。



为了让这种逻辑能正常工作，Netfilter 官方制定了推荐的优先级数值：

| **优先级 (整数值)** | **nft 关键字** | **内核常量**                 | **典型用途（链类型）**                    |
| ------------------- | -------------- | ---------------------------- | ----------------------------------------- |
| **-400**            | （无）         | `NF_IP_PRI_CONNTRACK_DEFRAG` | 数据包碎片整理（内核内部）                |
| **-300**            | `raw`          | `NF_IP_PRI_RAW`              | `raw` 表操作（例如 `NOTRACK`）            |
| **-225**            | （无）         | `NF_IP_PRI_SELINUX_FIRST`    | SELinux（首次检查）                       |
| **-200**            | （无）         | `NF_IP_PRI_CONNTRACK`        | **连接跟踪（Conntrack）**                 |
| **-150**            | `mangle`       | `NF_IP_PRI_MANGLE`           | `mangle` 操作（修改包，如 `TOS`、`MARK`） |
| **-100**            | `dstnat`       | `NF_IP_PRI_NAT_DST`          | `nat`（目标地址转换 DNAT）                |
| **0**               | `filter`       | `NF_IP_PRI_FILTER`           | `filter`（包过滤，如 `drop`, `accept`）   |
| **50**              | `security`     | `NF_IP_PRI_SECURITY`         | `security`（例如 `secmark`）              |
| **100**             | `srcnat`       | `NF_IP_PRI_NAT_SRC`          | `nat`（源地址转换 SNAT）                  |
| **225**             | （无）         | `NF_IP_PRI_SELINUX_LAST`     | SELinux（最后检查）                       |
| **300**             | （无）         | `NF_IP_PRI_CONNTRACK_HELPER` | 连接跟踪辅助（Helper）                    |



在 **nftables** 和网络防火墙的上下文中，**mangle** 意味着 “修改”、“篡改” 或 “操纵”。表格中的 **mangle** 表示**用于修改/标记用途的链**建议将优先级设置为 **-150**。



## **规则 (Rule)**

`规则` 是真正的执行单元，它包含“匹配条件”和“处理动作”。`nftables` 的语法更像 C 语言，非常结构化。

一条规则由一系列**表达式 (Expressions)** 组成。

- **匹配 (Matches):** 用于检查数据包的属性（如 `ip saddr` (源IP), `tcp dport` (目标端口), `ct state` (连接状态)）。
- **动作 (Actions/Statements):** 如果匹配成功，要执行的操作。
  - **终止动作 (Terminating):** `accept`, `drop`, `reject`。
  - **非终止动作 (Non-terminating):** `log` (记录), `counter` (计数), `nat dnat`, `nat snat` (地址转换) 等。

