# firwalld

**firewalld** 是一个动态的防火墙解决方案，专为在 Linux 系统上配置和管理网络过滤规则而设计。它通过与内核的 **netfilter** 框架进行交互，提供了一个用户友好的接口来管理防火墙规则。

firewalld 的核心设计目标是**简化防火墙配置**，并支持在不中断现有网络连接的情况下动态更新规则。

firewalld 主要由 **firewalld 守护进程** 和客户端工具 **firewall-cmd** 组成。它全面支持 IPv4、IPv6 和以太网桥接（ebtables），并提供了丰富的功能，包括对服务、端口、协议、IP 集（ipset）以及 ICMP 类型等的灵活管理。



与传统的 iptables 相比，firewalld 的优势在于：

1. **动态管理**：支持运行时修改规则，无需重启服务或断开现有连接。
2. **区域（Zone）概念**：通过“区域”来组织网络接口和来源，提供灵活的规则分组。
3. **支持服务抽象**：可以直接使用服务名称（如 http、ssh）而无需手动指定端口。
4. **分离运行时和永久配置**：运行时配置即时生效，永久配置在重启后生效。



## 概念

### 语法规则

**firewall-cmd** 是 firewalld 的主要命令行客户端工具，用于管理运行时和永久配置。以下是其语法规则的详细介绍：

```
firewall-cmd [OPTIONS...]
```

- **OPTIONS**：各种选项，用于指定要执行的操作、目标区域、策略或其他配置。
- 选项可以分为**通用选项**、**状态选项**、**区域/策略选项**、**直接接口选项**、**锁定选项**等。
- 选项支持运行时（默认）或永久（`--permanent`）配置。
- 某些选项支持多次指定（序列选项），如 `--add-service`、`--add-port` 等。





#### 选项顺序

选项的顺序通常不影响结果，但某些选项（如 **--permanent**）必须放在特定位置。



#### 运行时与永久配置

默认情况下，命令影响**运行时配置**（即时生效，重启后失效）。使用 **--permanent** 选项将更改保存到**永久配置**（重启后生效）。

要同时影响运行时和永久配置，需分别运行带和不带 **--permanent** 的命令。



#### 序列选项

某些选项（如 **--add-service**、 **--add-port**）可多次指定，firewalld 会处理所有指定的项。

成功执行至少一个项时，返回 0；否则返回错误码（如 **UNKNOWN_ERROR** 254）。



#### 区域

使用 **--zone=zone** 指定目标区域，未指定时默认使用 **--get-default-zone** 返回的区域。



#### 超时选项

**--timeout=timeval** 用于设置临时规则，时间格式为数字加单位（s 秒、m 分钟、h 小时），如 20m。

超时选项与 **--permanent** 不兼容。



#### 返回码

成功返回 0，失败返回特定错误码（如 **INVALID_PORT** 102、 **NOT_RUNNING** 252）。

查询选项（如 **--query-service**）返回 0（存在）或 1（不存在），除非发生错误。



### 优先级

firewalld 使用 **netfilter** 框架（Linux 内核的防火墙模块）来实现规则，规则的优先级决定了数据包的处理顺序。firewalld 的规则优先级基于以下层次，从高到低排列：

1. **紧急模式（Panic Mode）**

   当启用紧急模式（firewall-cmd --panic-on）时，所有流量都被丢弃，忽略所有其他规则。这是最高优先级。

2. **直接接口规则（Direct Rules，已废弃）**

3. **策略（Policies）**

4. **区域规则（Zone Rules）**

   区域（zone）是 firewalld 的核心概念，规则按区域应用，优先级取决于区域的绑定（接口或来源）和规则类型。

   firewalld 在匹配区域时，**优先**根据**来源（source ）**查找区域，如果没有匹配的来源，则根据**接口（interface）**查找区域。

5. **默认区域规则**

   如果数据包不匹配任何明确绑定的区域（接口或来源），则由默认区域（通过 firewall-cmd --get-default-zone 查看，通常为 public）处理。

6. **默认动作**

   如果数据包不匹配任何规则，区域的目标（target）决定其处理方式。



**区域内**的规则按以下顺序处理：

1. **富规则（Rich Rules）**
2. **服务选项（Service Options）**
3. **端口选项（Port Options）**
4. **其他规则**（如 **ICMP 阻止**、伪装、端口转发等）

如果数据包匹配区域中的高优先级规则（如富规则），后续规则（如服务或端口）不会被处理。



## 通用选项

**-h, --help**：显示帮助信息并退出程序。

**-V, --version**：用于显示 firewalld 的版本信息。

**-q, --quiet**：抑制状态消息输出，使程序运行更为安静。



## 状态选项

**--state**：检查 firewalld 守护进程是否运行。

**--reload**：重新加载防火墙规则，保留状态信息，运行时更改丢失。

**--complete-reload**：完全重新加载防火墙，包括 netfilter 模块，可能中断连接。

**--runtime-to-permanent**：将当前运行时配置保存为永久配置。





## 区域选项

**--get-default-zone**：获取默认区域。

**--set-default-zone=zone**：设置默认区域。



**--get-zones**：列出所有预定义或自定义区域（以空格分隔）。

**--get-active-zones**：列出活跃区域及其接口和来源。



**--permanent --new-zone=zone**：创建新永久区域。

**--permanent --delete-zone=zone**：删除指定的永久区域。区域必须为空（无接口、来源或规则）。

**--permanent --load-zone-defaults=zone**：加载区域的默认设置（仅适用于预定义区域）。



**--list-all-zones**：列出所有区域及其详细配置（包括接口、来源、服务、端口等）。

**--info-zone=zone**：显示指定区域的详细信息（类似 --list-all-zones 但仅针对一个区域）。



**--add-interface=interface**：将接口绑定到指定区域。

**--add-source=source[/mask]|MAC|ipset:ipset**：将来源（IP、网段、MAC 或 ipset）绑定到区域。



**--get-zone-of-interface=interface**：获取接口绑定的区域名称（若未绑定，返回“no zone”）。

**--get-zone-of-source=source[/mask]|MAC|ipset:ipset**：获取来源（IP、网段、MAC 或 ipset）绑定的区域名称。



### 接口和区域

在 firewalld 中，接口（interface）（如 eth0、wlan0）是网络设备的标识，**区域（zone）**定义了网络流量的信任级别和规则集。通过将接口绑定到区域，firewalld 决定如何处理通过该接口的流量。

**绑定规则**：

- 一个接口只能绑定到一个区域。
- 如果接口未明确绑定到任何区域，firewalld 会将其分配到**默认区域**（通过 firewall-cmd --get-default-zone 查看，通常为 public）。
- 绑定可以通过运行时（firewall-cmd --add-interface）或永久配置（firewall-cmd --permanent --add-interface）实现。



**绑定方式**：

- **手动绑定**：通过 firewall-cmd 命令明确指定区域。
- **自动绑定**：
  - 如果接口由 **NetworkManager** 管理，区域通常由连接配置文件（/etc/NetworkManager/system-connections/ 或 /etc/sysconfig/network-scripts/ifcfg-*）中的 ZONE= 设置决定。
  - 如果没有 ZONE= 设置，接口会绑定到默认区域。



当服务器启用一张新的物理网卡（例如 eth1），无论是通过硬件插入还是驱动加载，firewalld 的默认行为会根据当前的**网络管理方式和配置**而有所不同。

具体来说，如果**未执行任何 `firewall-cmd` 命令**（如 `--add-interface`），这张新网卡将不会自动绑定到任何自定义区域，而是会被**分配到默认区域**（通常是 `public` 区域）。

此外，如果新网卡由 **NetworkManager 管理**（这在大多数现代 Linux 发行版中是默认设置），firewalld 会进一步查询 NetworkManager 的连接配置文件。它会检查 `/etc/NetworkManager/system-connections/` 或 `/etc/sysconfig/network-scripts/ifcfg-*` 路径下的配置文件中是否有**`ZONE=` 设置**，并据此确定新网卡所属的防火墙区域。



### 默认动作

每个区域都有一个 默认动作（Default Action），也称为 目标（Target），它指定了当数据包不匹配区域内的任何具体规则（如富规则、服务选项、端口选项等）时，firewalld 如何处理该数据包。

默认动作是区域的最终处理方式，类似于防火墙规则链的默认策略（如 iptables 的 ACCEPT、DROP）。它决定了未被明确允许或拒绝的流量的命运。



**firewalld 支持以下四种默认动作：**

- ACCEPT：
  - 允许数据包通过，接受所有未被其他规则拒绝的流量。
  - 适用于信任度高的区域（如 trusted）。
- REJECT：
  - 拒绝数据包，并向发送方返回一个 ICMP 错误消息（如 icmp-host-prohibited）。
  - 适用于需要明确通知发送方的场景。
- DROP：
  - 丢弃数据包，不发送任何响应。
  - 适用于需要隐藏服务器存在的场景（如防止探测）。
- default：
  - 阻止所有未明确允许的传入连接
  - 允许系统正常地进行传出通信和对已建立连接的响应
  
- %%REJECT%%：
  - 内部目标，等同于 REJECT，但用于某些特殊场景（通常不直接设置）。



**默认动作的作用**

- **兜底处理**：当数据包不匹配区域内的富规则、服务、端口、ICMP 阻止、伪装或端口转发等规则时，默认动作决定其处理方式。
- **区域特性**：默认动作反映了区域的信任级别。例如：
  - **trusted** 区域的默认动作为 **ACCEPT**，允许所有流量。
  - **public** 区域的默认动作为 **default**，阻止所有未明确允许的传入连接。
  - **drop** 区域的默认动作为 **DROP**，丢弃所有流量。
  - **优先级**：默认动作的优先级最低，仅在没有其他规则匹配时生效。



与区域默认动作相关的参数主要通过 firewall-cmd 命令设置或查询，**且必须携带 --permanent 参数**。以下是主要参数：

**--get-target**：

- 查询区域的默认动作。
- 示例：`firewall-cmd --permanent --zone=public --get-target`

**--set-target=target**：

- 设置区域的默认动作（目标），支持 default、ACCEPT、REJECT、DROP。
- 示例：`firewall-cmd --permanent --zone=public --set-target=DROP`



## 服务选项

**--add-service=service [--timeout=timeval]**：添加服务到区域，允许服务相关的端口。

```
firewall-cmd --add-service=http
```

```
    firewall-cmd --add-service={http,https,ssh}
```

```
firewall-cmd --add-service=http --add-service=ssh
```



**--remove-service=service**：移除服务。

```
firewall-cmd --remove-service=http
```



**--list-services**：列出区域中启用的服务。

```
firewall-cmd --list-services
```



### 创建服务

firewalld 支持通过**命令行或配置文件**创建新服务。新服务属于永久配置，因此在创建时必须使用 `--permanent` 选项，并在创建后通过 `firewall-cmd --reload` 命令使其生效。以下是两种主要方式的详细说明：

使用 `firewall-cmd --permanent --new-service=service` 命令可以创建一个空的永久服务。创建服务后，需要通过其他命令为该服务添加端口、协议等属性。



**firewall-cmd --permanent --new-service=service**：在 /etc/firewalld/services/ 创建一个空的 XML 服务配置文件。

- 服务名称必须由字母、数字组成，并可包含下划线 `_` 和连字符 `-`。
- 服务名称不得与现有服务冲突（包括 `/usr/lib/firewalld/services/` 或 `/etc/firewalld/services/` 中的服务）。

```
firewall-cmd --permanent --new-service=myservice
```



以下命令为服务添加描述、端口、协议等属性（均需 --permanent）：

- `--set-description=description`：设置服务的详细描述。
- `--set-short=description`：设置服务的简短描述。
- `--add-port=portid[-portid]/protocol`：添加端口或端口范围。
- `--add-protocol=protocol`：添加协议。
- `--add-source-port=portid[-portid]/protocol`：添加源端口。
- `--add-helper=helper`：添加连接跟踪助手。
- `--set-destination=ipv:address[/mask]`：设置目标地址。
- `--add-include=service`：包含其他服务。



示例：

```
firewall-cmd --permanent --service=myservice --set-description="My custom web service"
firewall-cmd --permanent --service=myservice --set-short="Custom Web"
firewall-cmd --permanent --service=myservice --add-port=8080/tcp
firewall-cmd --permanent --service=myservice --add-protocol=http
firewall-cmd --permanent --service=myservice --add-source-port=1024-65535/tcp
```

完成后，**/etc/firewalld/services/myservice.xml** 可能如下：

```
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Custom Web</short>
  <description>My custom web service</description>
  <port port="8080" protocol="tcp"/>
  <protocol value="http"/>
  <source-port port="1024-65535" protocol="tcp"/>
</service>
```





## 端口选项

**--add-port=portid[-portid]/protocol [--timeout=timeval]**：添加端口或端口范围。

```
firewall-cmd --add-port=8080/tcp
firewall-cmd --add-port=3000-4000/udp
```

```
firewall-cmd --add-port=8080/tcp --add-port=9090/tcp
```

```
firewall-cmd --add-port={8080/tcp,8443/tcp,3306/tcp}
```



**--remove-port=portid[-portid]/protocol**：移除端口。

```
firewall-cmd --remove-port=8080/tcp
```



**--list-ports**：列出区域中启用的端口。

```
firewall-cmd --list-ports
```



**服务选项和端口选项可同时使用**：

```
firewall-cmd --add-service={http,https,ssh} --add-port={8080/tcp,8443/tcp,3306/tcp}
```

```
firewall-cmd --add-service=http --add-service=ssh --add-port=8080/tcp --add-port=9090/tcp
```



## 富规则

富规则（Rich Rules）是 firewalld 提供的高级规则定义方式，允许用户创建复杂的防火墙规则，超越简单的服务或端口配置。富规则使用一种结构化的语法，支持基于源地址、目标地址、端口、服务、协议、动作（如接受、拒绝、丢弃）等条件定义规则。

富规则适用于需要精细控制的场景，例如：

- 仅允许特定 IP 访问某服务。
- 限制特定端口的流量。
- 记录特定类型的流量。
- 配置复杂的转发规则。



富规则的优先级高于服务和端口规则，规则需精确匹配才能移除或查询。



### 语法

**富规则的语法**基本结构如下：

```
rule [family="ipv4|ipv6"]
    [source address="address[/mask]" [invert="true"]]
    [destination address="address[/mask]" [invert="true"]]
    [service name="service"]
    [port port="portid[-portid]" protocol="protocol"]
    [protocol value="protocol"]
    [icmp-block name="icmptype"]
    [icmp-type name="icmptype"]
    [masquerade]
    [forward-port port="portid" protocol="protocol" [to-port="portid"] [to-addr="address"]]
    [log [prefix="prefix"] [level="level"] [limit value="rate/duration"]]
    [audit [type="type"] [limit value="rate/duration"]]
    [action]
```

**关键字**：

- **rule**：规则的开始。
- **family**：指定协议族（ipv4 或 ipv6），默认根据上下文推断。
- **source**：源地址（IP 或网段），支持 invert="true"（反向匹配）。
- **destination**：目标地址，支持反向匹配。
- **service**：服务名称（如 http）。
- **port**：端口和协议（如 80/tcp）。
- **protocol**：协议（如 tcp、udp、自定义协议）。
- **icmp-block**：阻止 ICMP 类型。
- **icmp-type**：允许 ICMP 类型。
- **masquerade**：启用伪装（NAT）。
- **forward-port**：端口转发。
- **log**：记录匹配的流量。
- **audit**：审计匹配的流量。
- **action**：动作（如 accept、reject、drop、mark）。

**动作（action）**：

- **accept**：允许流量。
- **reject**：拒绝流量并返回错误（如 ICMP 拒绝消息）。
- **drop**：丢弃流量，无响应。
- **mark**：设置标记值（高级功能，需配合其他工具）。



### 参数

**协议族（Family）**

- 此参数用于**指定规则适用的网络协议族**，可选值为 `ipv4` 或 `ipv6`。
- 示例：`rule family="ipv4" ...`

**源/目标地址（Source/Destination）**

- 这些参数定义了**流量的源或目标地址**。它们支持多种形式，包括单个 IP 地址、IP 网段（例如 `192.168.1.0/24`），以及通过 `invert="true"` 实现的反向匹配。
- 示例：`source address="192.168.1.100"`，`destination address="10.0.0.0/8" invert="true"`。

**服务（Service）**

- 此参数用于**指定预定义的服务名称**，例如 `ssh` 或 `http`。
- 示例：`service name="http"`。

**端口（Port）**

- 用于**指定具体的端口号和协议类型**，支持单个端口或端口范围。
- 示例：`port port="8080" protocol="tcp"`。

**协议（Protocol）**

- 此参数用于**指定网络协议**，例如 `tcp`、`udp` 或其他自定义协议。
- 示例：`protocol value="icmp"`。

**ICMP 阻止/类型（ICMP-Block/ICMP-Type）**

- 这些参数用于**阻止或允许特定类型的 ICMP 消息**，例如 `echo-request`。
- 示例：`icmp-block name="echo-request"`。

**网络地址伪装（Masquerade）**

- 启用此参数将**激活网络地址伪装（NAT）功能**，这在路由器场景中尤为常见。
- 示例：`masquerade`。

**端口转发（Forward-Port）**

- 用于**配置端口转发规则**，需要指定源端口、协议、目标端口以及目标地址。
- 示例：`forward-port port="80" protocol="tcp" to-port="8080" to-addr="192.168.1.100"`。

**日志记录（Log）**

- 此参数用于**记录匹配到的网络流量**。可以指定日志前缀、日志级别（如 `emerg`、`alert`、`crit` 等），并设置日志速率限制。
- 示例：`log prefix="SSH_ACCESS" level="warning" limit value="3/m"`。

**审计（Audit）**

- 用于**审计匹配到的流量**，支持指定审计类型（如 `accept`、`reject`、`drop`）和速率限制。
- 示例：`audit type="accept" limit value="2/s"`。

**动作（Action）**

- 此参数**决定了对匹配流量的最终处理方式**。常见的动作包括 `accept`（接受）、`reject`（拒绝，可指定拒绝类型如 `icmp-admin-prohibited`）和 `drop`（丢弃）。
- 示例：`accept`，`reject type="icmp-admin-prohibited"`，`drop`。



### 命令

添加富规则，可指定超时

```
--add-rich-rule='rule' [--timeout=timeval]
```

示例：

```
firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.100" service name="ssh" accept'
firewall-cmd --add-rich-rule='rule family="ipv4" port port="8080" protocol="tcp" accept' --timeout=1h
```



移除富规则，需精确匹配规则字符串

```
--remove-rich-rule='rule'
```

示例：

```
firewall-cmd --remove-rich-rule='rule family="ipv4" source address="192.168.1.100" service name="ssh" accept'
```



查询富规则是否存在，返回 0（存在）或 1（不存在）

```
--query-rich-rule='rule'
```

示例：

```
firewall-cmd --query-rich-rule='rule family="ipv4" source address="192.168.1.100" service name="ssh" accept'
```



列出区域中的所有富规则。

```
--list-rich-rules
```

示例：

```
firewall-cmd --list-rich-rules
```



### 示例

**允许特定 IP 访问 SSH**：

```
firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.100" service name="ssh" accept'
```



**阻止特定网段的 ICMP 请求**：

```
firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" icmp-block name="echo-request" drop'
```



**记录 HTTP 访问并限制速率**：

```
firewall-cmd --add-rich-rule='rule family="ipv4" service name="http" log prefix="HTTP_ACCESS" level="notice" limit value="5/m" accept'
```



**端口转发**：

```
firewall-cmd --add-rich-rule='rule family="ipv4" forward-port port="80" protocol="tcp" to-port="8080" to-addr="192.168.1.100"'
```



## 紧急模式

在紧急模式下，所有入站和出站网络流量都会被 丢弃（DROP）。

**紧急模式是一种 运行时（Runtime） 配置，不存储在永久配置中。重启 firewalld 服务会导致 紧急模式（Panic Mode） 被关闭。**



**--panic-on**：启用紧急模式，丢弃所有流量。

```
firewall-cmd --panic-on
```



**--panic-off**：禁用紧急模式。

```
firewall-cmd --panic-off
```



## ICMP 阻止

ICMP（Internet Control Message Protocol）作为 IP 协议的组成部分，主要负责在网络中传递各类**控制消息**。这些消息包括但不限于**错误报告**（例如“目标不可达”）和**诊断信息**（如常用的 ping 命令）。

Firewalld 提供了对 ICMP 类型的精细化管理功能，允许用户根据需要**阻止或允许特定的 ICMP 消息**，例如 “echo-request” 或 “destination-unreachable” 等。

ICMP 类型在 IPv4 和 IPv6 协议中存在差异。Firewalld 为此提供了预定义的 ICMP 类型配置文件，这些文件通常存储在 `/usr/lib/firewalld/icmptypes/` 或 `/etc/firewalld/icmptypes/` 目录下。



以下是其中一些常见的 ICMP 类型：

- `address-unreachable`
- `destination-unreachable`：表示目标不可达。
- `echo-reply`：通常是 `ping` 命令的响应。
- `echo-request`：即 `ping` 请求。
- `parameter-problem`
- `redirect`
- `router-advertisement`
- `router-solicitation`
- `source-quench`
- `time-exceeded`：表示数据包的生存时间已耗尽。
- `timestamp-reply`
- `timestamp-request`



**--add-icmp-block=icmptype [--timeout=timeval]**：阻止指定 ICMP 类型。

```
firewall-cmd --add-icmp-block=echo-request
firewall-cmd --add-icmp-block=echo-request --timeout=1h
firewall-cmd --permanent --add-icmp-block=echo-request
```

阻止 echo-request 会禁用 ping 请求。



**--remove-icmp-block=icmptype**：移除 ICMP 阻止。

```
firewall-cmd --remove-icmp-block=echo-request
firewall-cmd --permanent --remove-icmp-block=echo-request
```



**--query-icmp-block=icmptype**：查询是否阻止了指定 ICMP 类型。

```
firewall-cmd --query-icmp-block=echo-request
```



**--list-icmp-blocks**：列出区域中阻止的 ICMP 类型。

```
firewall-cmd --list-icmp-blocks
```

