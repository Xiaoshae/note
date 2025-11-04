# iptables

## 钩子与内置链

**iptables 中存在 5 条内置链，分别对应 Netfilter 中的 5 个钩子**，以下是 Netfilter 钩子与内置链的对应关系:

| netfilter 钩子       | 内置        |
| -------------------- | ----------- |
| `NF_IP_PRE_ROUTING`  | PREROUTING  |
| `NF_IP_LOCAL_IN`     | INPUT       |
| `NF_IP_FORWARD`      | FORWARD     |
| `NF_IP_LOCAL_OUT`    | OUTPUT      |
| `NF_IP_POST_ROUTING` | POSTROUTING |



### 触发顺序

假设服务器知道如何路由数据包，而且防火墙允许数据包传输，下面就是不同场景下包的游走流程：

- 收到的、目的是本机的包：`PRETOUTING` -> `INPUT`
- 收到的、目的是其他主机的包：`PRETOUTING` -> `FORWARD` -> `POSTROUTING`
- 本地产生的包：`OUTPUT` -> `POSTROUTING`



考虑路由决策后的顺序。

- 收到的、目的是本机的包：`PRETOUTING` -> `路由决策` -> `INPUT`
- 收到的、目的是其他主机的包：`PRETOUTING` -> `路由决策` -> `FORWARD` -> `POSTROUTING`
- 本地产生的包：`路由决策` -> `OUTPUT` -> `POSTROUTING`



## 表

iptables 通过**表**对规则进行分类，每个表包含一组链（**并非所有表都包含全部链**），链中存放实际规则。

|          | PREROUTING | INPUT | FORWARD | OUTPUT | POSTROUTING |
| -------- | ---------- | ----- | ------- | ------ | ----------- |
| Raw      | √          |       |         | √      |             |
| Mangle   | √          | √     | √       | √      | √           |
| Nat      | √          |       |         | √      | √           |
| Filter   |            | √     | √       | √      |             |
| Security |            | √     | √       | √      |             |

**Raw** 表**仅包含 PREROUTING 和 OUTPUT 链**。

**Mangle** 表包含**所有链**。



注意：**同一表中的不同链**（如 filter 表的 INPUT 和 FORWARD），**以及不同表中的同名链**（如 filter 表的 INPUT 和 security 表的 INPUT），可配置的规则类型均不同。



### 表和链关系

`iptables`（用户空间工具）和 Netfilter（内核空间框架）在处理“表”与“链”时，展现了两种相反的逻辑模型：前者是“配置模型”，后者是“执行模型”。



**用户空间配置模型 (iptables)**

在用户空间配置规则时，`iptables` 命令行工具使用一种“表优先”的层级逻辑。

- **表 (Table)**：用户首先通过 `-t` 参数显式指定一个表（如 `filter` 或 `nat`）。表定义了规则的**功能上下文**。
- **链 (Chain)**：随后，用户在选定的表内指定一个在该表合法的链（如 `INPUT` 或 `PREROUTING`）。
- **规则 (Rule)**：最后，用户定义一条包含匹配标准（Matches）和动作（Target）的规则，并将其添加（-A）或插入（-I）到该表的特定链中。

**配置逻辑总结**：`表 -> 链 -> 规则`。



**内核空间执行模型 (Netfilter)**

在内核空间处理数据包时，Netfilter 框架采用一种“钩子优先”的执行逻辑。

- **钩子 (Hooks)**：这是内核协议栈中预定义的数据包截获点。它们在概念上对应于用户空间的“链”（如 `PREROUTING`、`INPUT` 等）。
- **表 (Tables)**：这是实现特定功能（如 `nat`、`filter`）的内核模块。它们通过注册回调函数的方式，将其规则处理逻辑“挂载”到指定的钩子上。

当一个数据包抵达某个钩子时，内核会严格按照预设的**优先级**（例如：raw -> mangle -> nat -> filter -> security），依次调用所有在该钩子上注册了处理逻辑的**表**，并执行其对应的规则链。



### 表优先级

虽然在 iptables 这个前端工具中，**链是包含在表里面的**。但是在 Netfiler 框架中，**表是用于区分一条链上的不同类型规则**。

当数据包到达 NF_IP_LOCAL_OUT 钩子时，会执行 OUTPUT 链上的规则。Raw 、Manager ... 等 5 个表都有 OUTPUT 链。系统内核会按照**固定顺序**执行 OUTPUT 链上的规则。具体顺序为：

1. 执行 OUTPUT 链上 **Raw** 表中的规则。
2. 执行 **Manager** 表中的规则。
3. 执行 **Nat** 表中的规则。
4. 执行 **Filter** 表中的规则。
5. 执行 **Security**表中的规则。



优先级：**Raw -> Mangle -> Nat -> Filter -> Security**





目标为本机的入站包：**PREROUTING → INPUT**

- 依次经过raw、mangle、nat(DNAT)表的PREROUTING链，再经mangle、filter、security、nat(SNAT)表的INPUT链。



## 规则

**规则**放置在**特定表**的**特定链**里面。当**链被调用**的时候，包会按优先级**依次匹配链里面的规则**。

规则由**匹配条件**与**目标动作**两部分构成，存储在特定表的链中。链被调用时，数据包将按顺序匹配链中所有规则。

**匹配条件**

通过灵活的组合条件识别目标流量，支持：

- 协议类型（TCP/UDP/ICMP等）
- 源/目标地址与端口
- 输入/输出接口
- 连接状态（NEW/ESTABLISHED等）
- 扩展模块（如字符串匹配、时间限制等）



**目标动作**

分为两类处理方式：

- **终止型目标**：如`ACCEPT`（放行）、`DROP`（静默丢弃）、`REJECT`（拒绝并响应）。触发后立即终止当前链的评估。
- **非终止型目标**：如`LOG`（记录日志）、`MARK`（打标记）。执行后继续评估后续规则。
- **跳转目标**：通过`-j`跳转至用户自定义链，实现模块化规则管理。自定义链处理完毕后返回原链继续执行，或通过`RETURN`提前返回。



### 用户自定义链

用户自定义链主要用于规则的组织管理。与直接关联系统数据包处理流程的内置链不同，自定义链需要通过"跳转"规则手动触发（例如使用-j参数指定链名）。当数据包进入自定义链后，存在两种返回原链的情况：

1) 遍历完自定义链所有规则未命中 
2) 规则触发RETURN动作。这种机制允许将规则集模块化，支持多级链式跳转，形成灵活的分层规则结构。



### 连接状态

连接状态在**规则匹配条件**中使用，连接跟踪系统中的连接状态有：

- `NEW`：如果到达的包关连不到任何已有的连接，但包是合法的，就为这个包创建一个新连接。对 面向连接的（connection-aware）的协议例如 TCP 以及非面向连接的（connectionless ）的协议例如 UDP 都适用
- `ESTABLISHED`：当一个连接收到应答方向的合法包时，状态从 `NEW` 变成 `ESTABLISHED`。对 TCP 这个合法包其实就是 `SYN/ACK` 包；对 UDP 和 ICMP 是源和目 的 IP 与原包相反的包
- `RELATED`：包不属于已有的连接，但是和已有的连接有一定关系。这可能是辅助连接（ helper connection），例如 FTP 数据传输连接，或者是其他协议试图建立连接时的 ICMP 应答包
- `INVALID`：包不属于已有连接，并且因为某些原因不能用来创建一个新连接，例如无法 识别、无法路由等等
- `UNTRACKED`：如果在 `raw` table 中标记为目标是 `UNTRACKED`，这个包将不会进入连 接跟踪系统
- `SNAT`：包的源地址被 NAT 修改之后会进入的虚拟状态。连接跟踪系统据此在收到反向包时对地址做反向转换
- `DNAT`：包的目的地址被 NAT 修改之后会进入的虚拟状态。连接跟踪系统据此在收到反向包时对地址做反向转换

这些状态可以定位到连接生命周期内部，管理员可以编写出更加细粒度、适用范围更大、更安全的规则。



## 命令

一个完整的 iptables 命令规则通常包含五个核心部分：表名、命令选项、链名、匹配条件和目标动作（或跳转）。



**基础部分**：

**表名**：指定规则所归属的表。常见的表包括 filter、nat、mangle 等。

**选项**：指定对规则链执行的管理操作，例如 -A (追加规则)、-D (删除规则)、-I (插入规则)、-L (列出规则)。

**链名**：指定规则所应用的具体内置链（如 INPUT, OUTPUT, FORWARD）或自定义链。



**规则的主体（即规则本身）由以下两个核心部分构成**：

1. **匹配条件**：定义数据包必须满足的一系列条件，以便被该规则处理。匹配条件可以基于多种因素，如协议类型（TCP, UDP）、源/目的 IP 地址、源/目的端口等。
2. **目标动作**：规定了当数据包完全满足所有匹配条件时，系统应执行的处置动作。这可以是一个最终动作（如 ACCEPT, DROP, REJECT），也可以是跳转（Jump）到另一个自定义链进行后续处理。





**语法格式**：

```
iptables [ -t 表名 ] 命令选项 [ 链名 ] [ 匹配条件 ] [ -j 目标动作或跳转 ]
```



### 表名

使用 `-t` 选项可以指定操作的表，默认是 filter 表。如果未指定表名并尝试在 POSTROUTING 链插入规则，系统会默认操作 filter 表的 POSTROUTING 链。由于 filter 表本身不存在这个链，最终会导致操作失败并报错。

支持的表名：

- **filter**
- **nat**
- **mangle**
- **raw**
- **security**



### 命令选项

| 选项         | 描述                                   |
| ------------ | -------------------------------------- |
| -A           | 在指定的链末尾追加一条新的规则         |
| -D           | 删除指定链中的一条规则                 |
| -I           | 在指定的链中插入一条新的规则           |
| -R           | 修改或替换指定链中的一条规则           |
| -L           | 列出指定链中的所有规则                 |
| -F           | 清空指定链中的所有规则                 |
| -N           | 新建一条用户自定义的规则链             |
| -X           | 删除指定表中用户自定义的规则链         |
| -P           | 设置指定链的默认策略                   |
| -n           | 以数字形式显示输出结果                 |
| -v           | 查看规则列表时显示详细信息             |
| -V           | 查看iptables 版本信息                  |
| -h           | 查看帮助信息                           |
| –line-number | 查看规则列表时，显示规则在链中的顺序号 |



### 链名

常见的**内建链**和**用户自定义扩展链**，具体名称如下：

- **PREROUTING**
- **INPUT**
- **FORWARD**
- **OUTPUT**
- **POSTROUTING**
- **用户自定义链**



## 匹配条件

匹配条件包括**基本匹配**和**扩展匹配**，**扩展匹配**又分为**隐式扩展**和**显式扩展**。

基本匹配：无需加载额外模块即可直接使用的匹配条件，属于 iptables 的**核心功能**。

| 匹配参数 | 说明                            |
| -------- | ------------------------------- |
| -p       | 指定规则协议，tcp udp icmp all  |
| -s       | 指定数据包的源地址，ip hostname |
| -d       | 指定目的地址                    |
| -i       | 输入接口                        |
| -o       | 输出接口                        |



**隐式扩展**：某些扩展匹配与协议强绑定，系统会根据 `-p` 参数**自动加载对应模块**，无需手动指定 `-m`。

当使用 `-p tcp` 时，系统会自动加载 tcp 模块，因此命令中 -m tcp 是可选参数（不影响命令结果）：

```
iptables -A INPUT [ -m tcp ] -p tcp --dport 22 -j ACCEPT
```

| 隐含扩展条件 | 需包含  | 扩展项     | 说明                                                         |
| ------------ | ------- | ---------- | ------------------------------------------------------------ |
| -m tcp       | -p tcp  | –sport     | 源端口                                                       |
|              |         | –dport     | 目标端口                                                     |
|              |         | –tcp-flags | 标志位检查（如 SYN,ACK,RST,FIN 的组合）                      |
|              |         | –syn       | 第一次握手                                                   |
| -m udp       | -p udp  | –sport     | 源端口                                                       |
|              |         | –dport     | 目标端口                                                     |
| -m icmp      | -p icmp | –icmp-type | 指定具体的ICMP消息类型：<br>8（Ping 请求包）<br>0（Ping 响应包） |



**显式扩展**：必须通过 `-m` 手动指定模块名称才能使用的扩展匹配，支持**复杂逻辑**或**跨协议功能**。

| 显示扩展条件 | 扩展项              | 说明                            |
| ------------ | ------------------- | ------------------------------- |
| -m state     | --state             | 检测连接的状态                  |
| -m multiport | --source-ports      | 多个源端口                      |
|              | --destination-ports | 多个目的端口                    |
|              | --ports             | 源和目的端口                    |
| -m limit     | --limit             | 速率(包/分钟)                   |
|              | --limit-burst       | 峰值速率                        |
| -m connlimit | --connlimit-above n | 多个条件                        |
| -m iprange   | --src-range ip-ip   | 源IP范围                        |
|              | --dst-range ip-ip   | 目的IP范围                      |
| -m mac       | --mac-source        | mac地址限制                     |
| -m string    | --algo [bm\|kmp]    | 匹配算法                        |
|              | --string "pattern"  | 要匹配的字符串                  |
| -m recent    | --name              | 设定列表名称                    |
|              | --rsource           | 源地址                          |
|              | --rdest             | 目的地址                        |
|              | --set               | 添加源地址的包到列表中          |
|              | --update            | 每次建立连接都更新列表          |
|              | --rcheck            | 检测地址是否在列表              |
|              | --seconds           | 指定时间内，与rcheck,update共用 |
|              | --hitcount          | 命中次数，与rcheck，update共用  |
|              | --remove            | 在列表中删除相应地址            |



## 目标动作（或跳转）

使用 `-j` 选项可以指定两类操作（**目标动作**或**跳转**）：

- **目标动作**：直接决定数据包的最终命运，**执行后不再匹配后续规则**。
- **跳转到自定义链**：将规则执行流程转移到用户自定义的规则链



**基础动作**：**无需加载额外模块**，直接支持的内置操作。

| 目标动作       | 说明                                                   |
| -------------- | ------------------------------------------------------ |
| `ACCEPT`       | 允许数据包通过。                                       |
| `DROP`         | 丢弃数据包（无响应）。                                 |
| `QUEUE`        | 将数据包移交到用户空间                                 |
| `RETURN`       | 退出当前链，返回上一级链继续处理。                     |
| `JUMP`（跳转） | 将数据包转发到用户自定义链处理（例如 `-j MY_CHAIN`）。 |



**扩展动作**：**需通过 `-m` 显式加载模块**，支持复杂操作。

| 目标动作     | 依赖模块/表   | 说明                                                         |
| ------------ | ------------- | ------------------------------------------------------------ |
| `REJECT`     | `-m reject`   | 拒绝数据包并返回响应（如 `--reject-with icmp-port-unreachable`）。 |
| `LOG`        | `-m log`      | 记录日志（如 `--log-prefix "Dropped: "`）。                  |
| `DNAT`       | `nat` 表      | 修改目的地址（用于端口转发，需在 `PREROUTING` 链）。         |
| `SNAT`       | `nat` 表      | 修改源地址（用于网络地址转换）。                             |
| `MASQUERADE` | `nat` 表      | 动态源地址伪装（适用于动态 IP 场景）。                       |
| `REDIRECT`   | `-m redirect` | 重定向数据包到本机端口（如将 80 端口重定向到 8080）。        |
| `CONNMARK`   | `-m connmark` | 标记连接（结合 `MARK` 用于流量控制）。                       |



## 典型示例

### 链默认行为

**默认策略（Policy）** 是 iptables 链（如 `INPUT`、`OUTPUT`、`FORWARD`）的最终行为。

如果**数据包未匹配任何规则**，则执行链的默认策略。常用策略：`ACCEPT`（允许）、`DROP`（丢弃）、`REJECT`（拒绝并返回响应）。



> **INPUT 和 OUTPUT 默认为 ACCEPT，FORWARD 默认为 DROP。**



设置默认策略的命令语法：

```
sudo iptables -P <链名> <策略>
```



将 INPUT 链默认行为设为 DROP（严格安全模式）

```
iptables -P INPUT DROP
```

- 所有未被明确允许的入站流量将被丢弃。



将 OUTPUT 链默认行为设为 ACCEPT（宽松出站）

```
iptables -P OUTPUT ACCEPT
```

- 允许所有未被明确禁止的出站流量。



将 FORWARD 链设为 REJECT（禁止路由转发）

```
iptables -P FORWARD REJECT
```

- 拒绝转发流量并返回 icmp-port-unreachable 响应。



### Filter

#### INPUT

允许 SSH、HTTP、HTTPS（22、80、443） 访问

```
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

- 允许 TCP 协议的 22 端口（SSH）、80 端口（HTTP）和 443 端口（HTTPS）访问本机。



允许 ICMP（Ping）

```
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
```

- 允许 ICMP 协议的 echo-request（Ping 请求）访问本机。



允许来自特定 IP 的访问

```
iptables -A INPUT -s 192.168.1.100 -j ACCEPT
```

- 允许来自 IP 地址 `192.168.1.100` 的所有流量访问本机。



允许已建立的连接

```
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

- 允许已建立的连接和相关的流量访问本机。



拒绝所有其他流量

```
iptables -A INPUT -j DROP
```

- 拒绝所有未明确允许的流量。



#### OUTPUT

允许本机访问外网

```
iptables -A OUTPUT -o eth0 -j ACCEPT
```

- 允许从本机通过外网接口 `eth0` 发出的所有流量。



允许本机访问 DNS

```
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
```

- 允许本机通过 UDP 协议的 53 端口（DNS）访问外部。



允许本机访问 HTTP 和 HTTPS

```
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPTiptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
```

- 允许本机通过 TCP 协议的 80 端口（HTTP）和 443 端口（HTTPS）访问外部。



允许本机 Ping 外部

```
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
```

- 允许本机发出 ICMP 协议的 `echo-request`（Ping 请求）。



允许已建立的连接

```
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

- 允许已建立的连接和相关的输出流量。



拒绝所有其他输出流量

```
iptables -A OUTPUT -j DROP
```

- 拒绝所有未明确允许的输出流量。



#### FORWARD

允许内网访问外

```
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
```

- 允许从内网接口 eth1 到外网接口 eth0 的转发流量。



这里仅允许 **eth1 网卡发送到 eth0** 的流量通过，但是由于**内网发送到外网**的数据包需要**接收返回的数据**，因此还需要允许 **eth0 到 eth1** 的流量通过。

```
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
```



如果您想**阻止来自外网的连接主动进入内网**，可以使用**连接追踪**（Connection Tracking）模块。

```
iptables -A FORWARD -i eth0 -o eth1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

**仅允许 ESTABLISHED (已建立的) 和 RELATED (相关的) 状态的包通过。**



允许外网访问内网特定服务

```
iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 80 -j ACCEPT
```

- 允许从外网接口 eth0 到内网接口 eth1 的 HTTP 流量。



允许已建立的连接

```
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
```

- 允许已建立的连接和相关的转发流量。



拒绝所有其他转发流量

```
iptables -A FORWARD -j DROP
```

- 拒绝所有未明确允许的转发流量。



### NAT

添加 NAT 规则，将 40000-50000 端口的 UDP 流量重定向到 443 端口：

```
sudo iptables -t nat -A PREROUTING -p udp --dport 40000:50000 -j REDIRECT --to-ports 443
```



## iptables 基本配置

- 启动iptables: `service iptables start`
- 关闭iptables: `service iptables stop`
- 重启iptables: `service iptables restart`
- 查看iptables状态: `service iptables status`
- 保存iptables配置: `service iptables save`
- iptables 服务配置文件: `/etc/sysconfig/iptables-config`
- iptables 规则保存文件: `/etc/sysconfig/iptables`
- 打开iptables 转发: `echo "1" > /proc/sys/net/ipv4/ip_forward`



### ubuntu

安装 iptables-persistent 工具

```
sudo apt update
sudo apt install iptables-persistent
```



自动保存 IPv4 (`rules.v4`) 和 IPv6 (`rules.v6`) 规则。

```
netfilter-persistent save
```



将当前规则保存到 `/etc/iptables/rules.v4` 以实现永久生效：

```
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```



将当前规则保存到 `/etc/iptables/rules.v6` 以实现永久生效：

```
sudo ip6tables-save | sudo tee /etc/iptables/rules.v6
```



将 `netfilter-persistent` 服务设置为开机自启。

```
systemctl enable netfilter-persistent
```



确认 `netfilter-persistent` 服务已启用，以便启动时加载规则：

```
systemctl status netfilter-persistent

● netfilter-persistent.service - netfilter persistent configuration
     Loaded: loaded (/usr/lib/systemd/system/netfilter-persistent.service; enabled; preset: enabled)
    Drop-In: /usr/lib/systemd/system/netfilter-persistent.service.d
             └─iptables.conf
     Active: active (exited) since Wed 2025-03-26 11:24:31 CST; 2min 17s ago
       Docs: man:netfilter-persistent(8)
   Main PID: 3158 (code=exited, status=0/SUCCESS)
        CPU: 6ms
```



临时启用 IP 转发

```
echo "1" > /proc/sys/net/ipv4/ip_forward
```



永久启用 IP 转发，编辑 `/etc/sysctl.conf` 文件添加以下行，并执行 `sysctl -p` 生效。

```
net.ipv4.ip_forward=1
```





### 开机自启

#### CentOS

第 1 步：安装 iptables-services

```
sudo dnf install iptables-services
```



第 2 步：创建和保存 iptables 规则

安装完成后，你可以像往常一样添加 `iptables` 规则。例如，你可以添加一个允许 SSH 连接的规则：

```
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```



当你添加完所有规则后，需要保存它们，这样 `iptables-services` 才能在系统启动时加载它们。

保存 IPv4 规则：

```
sudo iptables-save > /etc/sysconfig/iptables
```

保存 IPv6 规则：

```
sudo ip6tables-save > /etc/sysconfig/ip6tables
```

这些命令会将当前运行的规则保存到 `/etc/sysconfig/iptables` 和 `/etc/sysconfig/ip6tables` 文件中。



第 3 步：启用 iptables 服务

接下来，你需要启用 iptables 和 ip6tables 服务，并设置它们在系统启动时自动运行。

启用 IPv4 服务：

```
sudo systemctl enable iptables
```

启用 IPv6 服务：

```
sudo systemctl enable ip6tables
```



#### ubuntu

`iptables-persistent` 软件包是专为持久化 `iptables` 规则而设计的，它主要用于基于 Debian 的系统（如 Debian 和 Ubuntu）。



第 1 步：安装软件包

```
sudo apt update
sudo apt install iptables-persistent
```

安装过程中会弹出一个交互式界面，询问你是否要保存当前系统中的 IPv4 和 IPv6 规则。

- **问题 1：** "Do you want to save the current IPv4 rules?"
  - **选项：** `Yes` / `No`
  - **建议：** 如果你已经通过 `iptables` 命令设置了临时规则，选择 **Yes**，它会将这些规则保存到 `/etc/iptables/rules.v4` 文件中。如果你还没有设置任何规则，选择 `No`。
- **问题 2：** "Do you want to save the current IPv6 rules?"
  - **选项：** `Yes` / `No`
  - **建议：** 同上，根据你是否设置了 IPv6 规则来选择。



第 2 步：创建和编辑规则文件

软件包会将规则保存到以下文件：

- **IPv4 规则文件：** `/etc/iptables/rules.v4`
- **IPv6 规则文件：** `/etc/iptables/rules.v6`

你可以直接编辑这些文件来添加、修改或删除规则。这些文件的格式与 `iptables-save` 和 `ip6tables-save` 命令的输出格式完全相同。

**注意：** 如果你手动编辑了这些文件，需要**重新加载规则**才能让它们生效。



第 3 步：手动保存和加载规则

`iptables-persistent` 提供了两个命令来手动保存和加载规则，这在每次修改规则文件后都非常有用。

**保存规则：** 如果你通过 `iptables` 命令添加了新规则，可以使用以下命令将它们保存到规则文件中：

```
sudo netfilter-persistent save
```

这个命令会执行 `iptables-save > /etc/iptables/rules.v4` 和 `ip6tables-save > /etc/iptables/rules.v6` 的操作。



**加载规则：** 如果你手动编辑了规则文件，可以使用以下命令立即加载它们，而无需重启系统：

```
sudo netfilter-persistent reload
```

这个命令会执行 `iptables-restore < /etc/iptables/rules.v4` 和 `ip6tables-restore < /etc/iptables/rules.v6` 的操作。



