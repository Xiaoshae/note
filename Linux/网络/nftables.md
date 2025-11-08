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
- **input**



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

nftables 中的规则（rule）主要分为匹配部分（expressions）和动作部分（statements/verdicts），匹配部分用于检查数据包字段，动作部分决定对匹配数据包的处理。



### 匹配部分

匹配关键词主要由**表的地址簇（family）**和**链的钩子（hook）**决定，例如 inet 簇允许 IPv4 和 IPv6 相关匹配。

内核对数据包的处理是一个**状态逐步演进**的过程。在数据包的遍历路径上，内核会顺序执行解析（如 L3/L4 头部）、路由裁决以及（在适用时）与本地套接字的关联。

每一个 hook 都对应一个特定的上下文（context），该上下文**仅包含**截至该处理节点而已被内核解析和确定的元数据（metadata）。



一个规则所能使用的匹配（match）操作，**必须**基于在当前 hook 点已经可用的信息。

- 在 `PREROUTING` hook，数据包刚进入协议栈，路由决策尚未执行。因此，此时无法使用基于“输出接口”（`oif`）或“下一跳”信息的匹配项，因为这些元数据尚不存在。
- 在 `OUTPUT` hook，数据包由本地进程生成，其完整的套接字上下文（socket context）是已知的。因此，可以基于“用户 ID”（`uid`）或“进程组 ID”（`gid`）执行匹配，而这些匹配项在 `PREROUTING` hook 中是无效的。





### 动作部分

在 nftables 中，一个基础链（base chain）可用的动作（verdicts）和操作（statements），是由其 `type`（类型）和 `hook`（钩子）的组合严格定义的。



`type` 定义了链的**功能意图**，而 `hook` 定义了数据包在协议栈中的**处理阶段**。这两者共同构成了链的上下文（context），这个上下文直接约束了哪些操作在内核层面是有效和合乎逻辑的。



`type nat` 链的功能（地址转换）在内核中必须在**非常特定**的时间点执行，以确保路由和连接跟踪的正确性。

- **目标地址转换 (DNAT)** 必须在内核**首次**进行路由决策**之前**完成。如果内核先根据原始（公网）目标 IP 进行了路由（例如判定数据包是用于 `input` 还是 `forward`），之后再修改目标 IP（改为内网 IP），路由决策就完全错误了。
- **源地址转换 (SNAT / Masquerade)** 必须在内核**最后**进行路由决策**之后**完成。内核必须先用真实的（内网）源 IP 完成所有路由和过滤，确定数据包将从哪个接口（`oif`）离开。在数据包即将发出的最后一刻，才将其源 IP（内网 IP）改写为（公网）IP。



## 语法

**nft** 是用于在 Linux 内核的 nftables 框架中设置、维护和检查数据包过滤与分类规则的命令行工具。其规则集（ruleset）由一系列嵌套的结构组成：表（Tables）、链（Chains）、规则（Rules），以及辅助对象如 集合（Sets） 和 映射（Maps） 等。



**nft** 命令**基本语法结构**如下：

```
nft [ -nNscaeSupyjtT ] [ -I directory ] [ -f filename | -i | cmd ...]
nft -h
nft -v
```



```
nft [选项] [命令...]
```

**[选项]**：

**[命令...]**：用于设置、维护和检查规则集的操作，例如 `add table`、`list ruleset` 等。





### 表（Table）

表是链、集合及有状态对象的容器，通过其**地址族和名称进行标识**。

地址族必须是 ip、ip6、inet、arp、bridge、netdev 之一。inet 地址族是一个虚拟族，用于创建 IPv4/IPv6 混合表。若**未指定地址族，默认使用 ip**。

添加与创建之间的唯一区别在于，如果你要操作的那个表已经存在了，使用**添加命令尝试创建一个新表**，不会触发错误（它会忽略这个操作或视为已完成），而**使用创建命令则会报错**（因为它要求表必须是新创建的，不能已存在）。

```
{add | create} table [family] table [{ [comment comment ;] [flags flags ;] }]
{delete | destroy | list | flush} table [family] table
list tables [family]
delete table [family] handle handle
destroy table [family] handle handle
```





### 链（Chains）

链是规则的容器，分为基础链和常规链两种类型。基础链是网络堆栈中数据包的入口点，而常规链可作为跳转目标，用于更好地组织规则。常规链可以是匿名的，具体示例请参阅裁决声明部分。



**语法规则**：

```
{add | create} chain [family] table chain [{ type type hook hook [device device] priority priority ; [policy policy ;] [comment comment ;] }]
{delete | destroy | list | flush} chain [family] table chain
list chains [family]
delete chain [family] table handle handle
destroy chain [family] table handle handle
rename chain [family] table chain newname
```



**命令详解**：

| 命令        | 描述                                                         |
| ----------- | ------------------------------------------------------------ |
| **add**     | 在指定表中添加新链。**当指定了钩子和优先级值时，该链将作为基础链**创建并挂接到网络堆栈中。 |
| **create**  | 与添加命令类似，但如果链已存在，则返回错误。                 |
| **delete**  | 删除指定的链。该链不得包含任何规则，也不能作为跳转目标使用。 |
| **destroy** | 删除指定的链，如果链不存在也不会失败。该链不得包含任何规则，也不能作为跳转目标使用。 |
| **rename**  | 重命名指定的链。                                             |
| **list**    | 列出指定链的所有规则。                                       |
| **flush**   | 清空指定链的所有规则。                                       |

对于基础链，类型、钩子和优先级参数是必需的。



**支持的链类型**：

| **类型** | **协议簇**    | **Hooks**                              | 描述                                                         |
| -------- | ------------- | -------------------------------------- | ------------------------------------------------------------ |
| filter   | all           | all                                    | 在不确定时使用的标准链类型。                                 |
| nat      | ip, ip6, inet | prerouting, input, output, postrouting | 此类链基于连接跟踪条目执行本机地址转换。只有连接的首个数据包实际经过此链——其规则通常定义了创建的连接跟踪条目的详细信息（例如 NAT 语句）。 |
| route    | ip, ip6, inet | output                                 | 如果数据包已遍历此类链且即将被接受，当 IP 报头的相关部分发生变化时，将执行新的路由查找。这允许在 nftables 中实现策略路由选择器等功能。 |



优先级参数接受一个有符号整数值或标准优先级名称，用于指定具有相同钩子值的链被遍历的顺序。排序是升序的，即较低的优先级值比较高的优先级值具有优先权。

在使用 NAT 类型链时，优先级值有一个较低的排除下限-200，因为连接跟踪钩子在此优先级运行，而 NAT 功能需要这一设定。

标准优先级值可以用易于记忆的名称替代。并非所有名称在每个协议族和每个钩子中都适用（请参阅下方的兼容性矩阵），但其数值仍可用于链的优先级排序。 

| **名称** | **价值** | 簇                         | **Hooks**   |
| -------- | -------- | -------------------------- | ----------- |
| raw      | -300     | ip, ip6, inet              | all         |
| mangle   | -150     | ip, ip6, inet              | all         |
| dstnat   | -100     | ip, ip6, inet              | prerouting  |
| filter   | 0        | ip, ip6, inet, arp, netdev | all         |
| security | 50       | ip, ip6, inet              | all         |
| srcnat   | 100      | ip, ip6, inet              | postrouting |



### 规则（Rules）

规则被添加到指定表中的链中。若未指定协议族，则默认使用 ip 族。根据一系列语法规则，规则由两种组件构成：表达式和语句。

add 和 insert  命令支持一个可选的位置指示符，该指示符可以是现有规则的句柄或索引（从零开始）。在内部，规则位置始终通过句柄来标识，而从索引到句柄的转换发生在用户空间。这带来两个潜在影响：如果在转换完成后发生并发规则集变更，若在引用规则之前插入或删除了规则，则实际规则索引可能会发生变化。如果引用的规则已被删除，内核将拒绝该命令，如同提供了无效句柄一样。

注释可以是单个词或双引号（"）内的多词字符串，用于对实际规则进行备注。注意：若使用 bash 添加规则，需对引号进行转义，例如：\"enable ssh for servers\"。

```
{add | insert} rule [family] table chain [handle handle | index index] statement ... [comment comment]
replace rule [family] table chain handle handle statement ... [comment comment]
{delete | reset} rule [family] table chain handle handle
destroy rule [family] table chain handle handle
reset rules [family] [table [chain]]
```



| 命令        | 描述                                                         |
| ----------- | ------------------------------------------------------------ |
| **add**     | 添加一条由语句列表描述的新规则。除非指定了位置，否则该规则将附加到给定链中；若指定了位置，则在该指定规则之后插入此规则。 |
| **inser**   | 与 add 相同，但规则会插入到链的开头或指定规则之前。          |
| **replace** | 与添加类似，但此规则会替换指定的规则。                       |
| **delete**  | 删除指定规则。                                               |
| **destroy** | 删除指定规则，即使规则不存在也不会失败。                     |
| **reset**   | 重置包含规则的状态，例如计数器和配额声明值。                 |



**向 iptables 输出链添加一条规则。**

```
nft add rule filter output ip daddr 192.168.0.0/24 accept # 'ip filter' is assumed
# same command, slightly more verbose
nft add rule ip filter output ip daddr 192.168.0.0/24 accept
```



**查询规则句柄**

要删除或替换规则，您首先需要知道它的**句柄 (handle)**。您可以使用 `list ruleset` 命令并添加 `-a` (或 `--handle`) 标志来查看所有规则及其句柄。

```
nft -a list ruleset
```



**示例输出：**

```
table inet filter {
          chain input {
                  type filter hook input priority filter; policy accept;
                  ct state established,related accept # handle 4
                  ip saddr 10.1.1.1 tcp dport ssh accept # handle 5
            ...
```

在-这个例子中，`ip saddr 10.1.1.1 tcp dport ssh accept` 这条规则的句柄是 **5**。



**从 inet 表中删除规则。**

使用 `delete` 命令，并指定规则的 `family`、`table`、`chain` 和 `handle`。

**语法**：

```
delete rule [family] table chain handle <handle_number>
```

**示例：** 要删除上面示例中句柄为 5 的规则：

```
nft delete rule inet filter input handle 5
```



**替换规则**

使用 `replace` 命令。您需要指定要替换规则的 `handle`，然后提供**全新的规则语句**。

**语法**：

```
replace rule [family] table chain handle <handle_number> <new_statement> ...
```



**示例：** 假设您想将句柄 5 的规则（只允许 `10.1.1.1`）更改为允许整个 `10.1.1.0/24` 网段访问 SSH：

```
nft replace rule inet filter input handle 5 ip saddr 10.1.1.0/24 tcp dport ssh accept
```

*（请注意：此命令会用全新的语句完全替换掉句柄 5 对应的旧规则。）*



## 匹配规则 (Matches)



### 元数据 (Meta)



这是最常用的一类匹配，用于检查与数据包本身内容无关的元信息。

- `iif` / `iifname`: 匹配数据包的**入接口** (Input Interface)。
  - 示例: `iifname "eth0"` (从 "eth0" 接口进入)
  - 示例: `iif type loopback` (从环回接口进入)
- `oif` / `oifname`: 匹配数据包的**出接口** (Output Interface)。
  - 示例: `oifname "ppp0"` (从 "ppp0" 接口出去)
- `l4proto`: 匹配第四层（传输层）协议。这是 `inet` 簇中统一匹配 L4 协议的最佳方式。
  - 示例: `meta l4proto tcp`
  - 示例: `meta l4proto { tcp, udp }`
  - 示例: `meta l4proto { icmp, icmpv6 }` (同时匹配 ICMPv4 和 ICMPv6)
- `protocol`: 匹配第三层（网络层）协议。
  - 示例: `meta protocol ip` (仅 IPv4)
  - 示例: `meta protocol ip6` (仅 IPv6)
- `mark`: 匹配数据包的防火墙标记 (firewall mark)。
  - 示例: `mark 0x1`
- `priority`: 匹配数据包的 QoS 优先级。



1.2. 连接跟踪 (Connection Tracking) 匹配



连接跟踪（conntrack）是状态防火墙的核心。`ct` 匹配检查数据包在连接跟踪表中的状态。

- `ct state`: 匹配连接的状态。
  - `established`: 属于一个已建立的连接。
  - `related`: 与一个已建立的连接相关（例如 FTP 的数据连接或 ICMP 错误包）。
  - `new`: 正在尝试建立一个新连接。
  - `invalid`: 无法识别的无效数据包。
  - **常用组合**: `ct state { established, related }` (匹配所有“已知的”合法流量)
- `ct proto`: 匹配连接的 L4 协议。
  - 示例: `ct proto tcp`
- `ct status`: 匹配连接的 NAT 状态。
  - `snat`: 匹配已经（或将要）被 SNAT 的包。
  - `dnat`: 匹配已经（或将要）被 DNAT 的包。
- `ct direction`: 匹配数据包的方向。
  - `original`: 原始方向（例如，客户端 -> 服务器）。
  - `reply`: 回复方向（例如，服务器 -> 客户端）。



### 网络层 (L3) 



用于检查 IP 头部信息。`inet` 簇会智能地处理 v4 和 v6。

- `ip saddr` / `ip daddr`: 匹配 **IPv4** 源/目的地址。
  - 示例: `ip saddr 192.168.1.100`
  - 示例: `ip daddr 1.1.1.1`
- `ip6 saddr` / `ip6 daddr`: 匹配 **IPv6** 源/目的地址。
  - 示例: `ip6 saddr fe80::1`
  - 示例: `ip6 daddr 2001:db8::1`
- **统一匹配 (使用集合)**: `inet` 簇的强大之处在于可以使用集合同时定义 v4 和 v6 地址。
  - `define allowed_hosts = { 192.168.1.0/24, 2001:db8:1::/64 }`
  - `ip saddr @allowed_hosts` (v4 包会匹配 v4 地址)
  - `ip6 saddr @allowed_hosts` (v6 包会匹配 v6 地址)
- `fib`: 匹配转发信息库 (FIB)。这是一个高级匹配，用于检查内核将如何路由该数据包。
  - 示例: `fib saddr .iif oif "eth1"` (检查源地址是否可以通过 "eth1" 接口路由出去)



### 传输层 (L4) 



用于检查 TCP、UDP、ICMP 等协议的头部信息。

- **TCP**:
  - `tcp sport` / `tcp dport`: 匹配 TCP 源/目的端口。
  - 示例: `tcp dport 22` (目标端口为 SSH)
  - 示例: `tcp dport { 80, 443 }` (目标端口为 HTTP 或 HTTPS)
  - `tcp flags`: 匹配 TCP 标志位。
  - 示例: `tcp flags & (syn|ack) == syn` (匹配 SYN 包)
- **UDP**:
  - `udp sport` / `udp dport`: 匹配 UDP 源/目的端口。
  - 示例: `udp dport 53` (目标端口为 DNS)
- **ICMP (v4)**:
  - `icmp type`: 匹配 ICMPv4 类型。
  - 示例: `icmp type echo-request` (Ping 请求)
- **ICMPv6**:
  - `icmpv6 type`: 匹配 ICMPv6 类型。
  - 示例: `icmpv6 type echo-request`



**注意**: 在 `inet` 簇中，当您写 `tcp dport 22` 时，`nftables` 会自动查找 L4 协议（通过 `meta l4proto tcp`），因此它同时适用于 IPv4 和 IPv6 上的 TCP 流量。



## 目标动作 (Targets / Verdicts)

### 终止动作 (Terminating Actions)



一旦数据包匹配到这些动作，它将**立即停止**在当前链中的处理，并作出最终裁决。

- `accept`: **接受**数据包。数据包将继续在内核中传递（例如，传递给本地应用程序或进行转发）。
- `drop`: **丢弃**数据包。数据包被“悄悄地”丢弃，不会向发送方发送任何通知。
- `reject`: **拒绝**数据包。数据包被丢弃，但会向发送方发送一个 ICMP 错误消息（例如 `port-unreachable` 或 `host-unreachable`）。
  - 示例: `reject with tcp reset` (对于 TCP，发送 RST 包)
  - 示例: `reject with icmp admin-prohibited` (发送 ICMP 管理员禁止)



### 非终止动作 



这些动作会对数据包执行一项操作，但**不会停止**它在当前链中的处理（除非显式配置）。

- `log`: **记录**数据包信息。通常用于调试。
  - 示例: `log prefix "Dropped Packet: " level info`
- `counter`: **计数**。`nftables` 会自动为匹配此规则的数据包和字节数进行计数。
  - 示例: `counter` (只需这一个词)
- `masquerade`: **地址伪装**。一种特殊的 SNAT，通常用于 `postrouting` 链。它会自动将源 IP 更改为出接口的 IP 地址。非常适用于 IP 地址动态变化（如 PPoE）的场景。
  - 示例: `masquerade`
- `snat`: **源地址转换 (Source NAT)**。用于 `postrouting` 链，将数据包的源 IP 更改为指定的 IP 地址。
  - 示例: `snat to 1.2.3.4` (固定 IP)
  - 示例: `snat to 1.2.3.4:10000-20000` (指定 IP 和端口范围)
- `dnat`: **目的地址转换 (Destination NAT)**。用于 `prerouting` 链，将数据包的目的 IP（和端口）更改为内部服务器的 IP（和端口）。
  - 示例: `dnat to 192.168.1.100`
  - 示例: `dnat to 192.168.1.100:8080` (端口转发)
- `redirect`: **重定向**。一种特殊的 DNAT，将数据包重定向到**本机**的某个端口，常用于透明代理。
  - 示例: `redirect to 8080`



### 控制流动作 (Control Flow)

这些动作用于管理规则的处理流程，通常用于跳转到自定义链。

- `jump <chain_name>`: **跳转**到指定的链。处理完该链后，如果该链没有终止动作，处理流程会**返回**到原始链的下一条规则。
- `goto <chain_name>`: **转到**指定的链。处理完该链后，**不会返回**原始链，而是从新链中作出最终裁决。
- `return`: 从 `jump` 过来的自定义链中**返回**到调用它的链。



## 示例

### 从文件中加载规则

加载规则的主要命令是 `nft -f <filename>` 或 `nft --file <filename>`。

`nftables` 语法支持 `include` 语句来嵌入其他文件的内容。



假设主配置文件为 `/etc/nftables.conf`，在主配置文件里面使用 `include` 指令来引用文件夹中的所有文件。

```
#!/usr/sbin/nft -f

# 清空所有旧规则（可选）
# flush ruleset

# 定义表和链（通常在主文件或基础规则中完成）
# table ip filter {
#     chain input { ... }
# }

# 🚀 使用 include 指令加载文件夹中的所有 .nft 文件
# nftables 会按照文件系统的顺序加载这些文件
include "/etc/nftables/rules.d/*.nft"

# 另一个示例，加载子目录中的所有文件
# include "/etc/nftables/custom_zones/*/rules.nft"
```



只需加载这个主配置文件，`nftables` 解析器会自动处理 `include` 语句，并将所有子文件合并为一个规则集进行加载。

```
nft -f /etc/nftables.conf
```



`nft -f <filename>` 命令本身的意思是“从文件中读取并执行 `nftables` 命令”。它**不**会自动清空（替换）现有规则。

如果你希望加载文件时，**清空**所有旧规则，**仅使用**文件中的新规则，那么你的规则文件**必须**在最开始的位置包含 `flush ruleset` 命令。
