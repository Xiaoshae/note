# alpine



## dhcp

DHCP 协议设计于网络带宽和设备处理能力都相对有限的时代。如果服务器把所有可能配置的选项（可能有几十个）都塞进一个 DHCP 响应包里，无论客户端是否需要，都会造成不必要的网络流量和客户端处理负担。

在 DHCP 交互过程中，特别是客户端发送的 DHCPDISCOVER 和 DHCPREQUEST 报文中，会包含 **Option 55 (Parameter Request List)**。

该列表明确告知 DHCP 服务器客户端所期望获得的配置参数，例如 **Option 1 (Subnet Mask)**、**Option 3 (Router)**、**Option 6 (Domain Name Server)**、**Option 42 (Network Time Protocol Servers)** 以及 **Option 121 (Classless Static Route)** 等。

**DHCP 服务器（如 dnsmasq）严格遵循此列表。** 只有当客户端的 Option 55 明确请求了某一特定选项（例如 Option 121）时，服务器才会在 **DHCPOFFER** 或 **DHCPACK** 报文中包含并返回该选项的配置信息。

因此，如果客户端的 **Parameter Request List (Option 55)** 中未包含 **Option 121**，则即使 DHCP 服务器（dnsmasq）已配置了 **无类别静态路由** 信息，它也不会在响应报文中向客户端下发此配置。



在 Alpine Linux 中，udhcp（udhcpc 客户端）默认情况下**不会**主动请求或接受 DHCP 服务器通过选项 121 (classless-static-route) 指定的特定静态路由。您需要明确配置 udhcpc 来请求这个选项。

为了让 udhcp 在通过 /etc/network/interfaces 启动时能够接受特定的静态路由，您需要修改您的配置文件，使用 udhcpc_opts 来传递额外的参数给 udhcpc 客户端。

具体来说，您需要请求 "classless static routes" 选项，该选项的编号是 121。



请按照以下方式修改您的 /etc/network/interfaces 文件，为您想要配置的接口（在您的例子中是 eth1）添加 udhcpc_opts -O 121 这一行：

```
auto eth1
iface eth1 inet dhcp
    udhcpc_opts -O 121
```

udhcpc_opts -O 121: 这是关键部分。它告诉 ifup 在调用 udhcpc 命令时，增加 -O 121 这个参数。-O 参数用于向 DHCP 服务器请求特定的选项。通过请求选项 121，udhcpc 会告诉 DHCP 服务器它能够理解并处理无类别静态路由。



**`udhcpc_opts -O <option>` 这个参数会完全覆盖 udhcpc 默认请求的选项列表，而不是在原有列表上追加。**

在不加 udhcpc_opts 参数时，Alpine 的 udhcpc 客户端会默认向 DHCP 服务器请求一个标准的选项集合，这个集合里通常包含了：

- Option 1: Subnet Mask (子网掩码)
- **Option 3: Router (路由器/网关)**
- Option 6: Domain Name Server (DNS 服务器)
- Option 15: Domain Name (域名)
- 等等...



**默认行为 (无 `udhcpc_opts` 时):**

Alpine Linux 的 `udhcpc` 客户端在默认情况下，会发送一个标准的 **Parameter Request List (Option 55)**，通常包含一套基础且关键的网络配置选项，例如：

- **Option 1 (Subnet Mask)**
- **Option 3 (Router)**
- **Option 6 (Domain Name Server)**
- **Option 15 (Domain Name)**
- 以及其他标准选项。

**定制行为 (使用 `udhcpc_opts -O 121` 时):**

通过配置 `udhcpc_opts -O 121`，实际上是通过 `ifup` 程序将 `-O 121` 参数传递给了 `udhcpc` 客户端。在 `udhcpc` 中，`-O` 参数用于**替换**（Overwrite）或**定制**默认的 **Option 55 (Parameter Request List)**。

这将导致客户端发出的 DHCP 请求报文中的 **Option 55 (Parameter Request List)** 仅包含 **Option 121**，表明客户端仅请求获取 **无类别静态路由** 信息。

DHCP 服务器严格依据客户端在 **Option 55** 中列出的请求选项进行响应。当服务器发现客户端的请求列表中**仅包含 Option 121**，它在 **DHCPOFFER/DHCPACK** 报文中将**不会**包含客户端未请求的基础配置，特别是 **Option 3 (Router / 网关)**。



要解决这个问题，您需要在请求 Option 121 的**同时**，明确地把默认网关 (Option 3) 以及其他您需要的标准选项也一并请求回来。

请修改您的 /etc/network/interfaces 文件如下：

```
auto eth1
iface eth1 inet dhcp
    # 同时请求 网关(3)、DNS(6)、域名(15) 和 无类别静态路由(121)
    udhcpc_opts -O 3 -O 6 -O 15 -O 121
```



使用 ifdown 和 ifup 重启网卡即可生效。

```
ifdown eth1
ifup eth1
```

