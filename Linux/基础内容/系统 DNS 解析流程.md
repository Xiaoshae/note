# Linux DNS 解析全过程

## 什么是 DNS 解析？

DNS 解析（DNS Resolution）是一种将域名（例如 **example.com**）转换为对应的 IP 地址（例如 192.0.2.1）的过程。这是一个核心的互联网服务，允许用户使用易记的域名来访问网站，而不是直接使用复杂的数字 IP 地址。



在 Linux 中， DNS 解析过程由**解析库**（Resolver Library）、配置文件和 DNS 服务器共同完成。Resolver 是程序用来查询域名的工具，配置文件告诉它去哪里查找答案，而 DNS 服务器则提供最终的 IP 地址。

在下文中我们将使用 **Resolver** 来表示术语**解析库**。



## Resolver

**Resolver** 知道如何进行 **DNS 查询**，但它本身不存储 DNS 结果，而是根据配置文件决定如何查找域名对应的 IP 地址。

**Resolver** 是 Linux DNS 解析的核心，它是 C 标准库（如 glibc）的一部分，并包含一些关键函数，比如 **gethostbyname** 和 **getaddrinfo**。



~~Resolver 具有较弱的缓存能力，主要缓存 **DNS 服务器地址**（来自 /etc/resolv.conf）和**短暂的 DNS 查询结果**（如 A 记录、AAAA 记录）。其缓存内容包括域名到 IP 地址的映射，但通常不包含复杂的记录类型（如 SRV、TXT）或长期存储的数据。~~

~~这种缓存是临时的，基于短时间的**TTL（生存时间）**，并且缺乏高级管理功能。~~

当我询问 AI 时，它提到 Resolver 具有**较弱的缓存能力**。我在 Arch Linux Wiki 的 [Domain name resolution（域名解析）](https://wiki.archlinux.org/title/Domain_name_resolution) 文章中看到**Note:** The glibc resolver does not cache queries.（**注意**：glibc 解析器不会缓存查询。）



**Resolver（glibc 解析器）不会缓存查询。**



当你运行 **ping example.com** 或 **curl example.com** 时，应用程序（如 ping 或 curl）会调用相关函数来请求域名的 IP 地址，例如源代码中可能类似于 **ip = getaddrinfo("example.com")**，此时 **Resolver** 就会知道应用程序要求查询 **example.com** 的 IP 地址。



## 配置文件

在 Linux 系统上，DNS 解析主要由三个配置文件控制：***/etc/nsswitch.conf*（定义名称服务顺序）**、***/etc/hosts*（处理本地主机映射）**和  ***/etc/resolv.conf*（指定 DNS 服务器）**。



**/etc/nsswitch.conf** 文件（全称 **Name Service Switch**，也称为名称服务切换）用于**指定 Resolver 进行查询 DNS 的顺序**。它的**关键部分**是 **hosts 行**，通常是这样的：

```
hosts:          files dns
```

**hosts** 定义了 Resolver 进行 DNS 查询的顺序，从**左到右**依次进行查询。这意味着，先查询本地文件 **/etc/hosts** 中的 DNS 记录；如果未找到，则通过 DNS 服务器进行查询。

- **files**：查询本地文件 /etc/hosts。
- **dns**：查询 DNS 服务器。



hosts 不仅支持 files 和 dns 参数，还支持其他选项，例如 **myhostname**。需要注意的是，未在 hosts 行中明确指定的选项将不会被 **Resolver** 使用。

即使未在 hosts 行中明确指定 myhostname 选项，也不意味着 **Resolver** 无法通过主机名获取本地 IP 地址。如果 hosts 指定了 dns，**Resolver** 会读取 /etc/hosts 文件中的 nameserver。在 Ubuntu 系统中，nameserver 通常被 systemd-resolved 修改为 127.0.0.53，DNS 解析请求会发送至 systemd-resolved 守护进程，而 systemd-resolved 会尝试通过主机名获取本地 IP 地址。



Resolver 首先查询本地文件 **/etc/hosts** 中的 DNS 记录，它是一个简单的文本文件，用于手动配置域名和 IP 地址的映射。例如：

```
192.168.100.100	web1.example.com
192.168.200.200	web2.example.com
```



如果 **/etc/hosts** 中没有相应的域名， Resolver 会读取 **/etc/resolv.conf** 文件，它用于存放 DNS 服务器地址，Resolver 会向这些 DNS 服务器发送请求。

```
nameserver 127.0.0.53
options edns0 trust-ad
search .
```



`/etc/resolv.conf` 是一个简单的文本配置文件。它由一行一行指令组成，每行以一个指令关键字开头，后跟一个或多个参数。文件不区分大小写，且每行指令之间可以用空格或制表符分隔。注释行以 `#` 开头。

```
# 这是一个注释行
nameserver 223.5.5.5
nameserver 223.6.6.6

search example.com subdomain.example.com
domain localdomain

options timeout:5 attempts:2 ndots:1
```

- **nameserver**：指定 DNS 服务器的 IP 地址。**只能有三个 nameserver 条目**。
- **search**：指定域名搜索列表，实际作用略。
- **domain**：指定本地域名，实际作用略。
- **options**：指定 DNS 解析选项，用于自定义行为。
  - **timeout**：超时时间
  - **attempts**：重试次数
  - **ndots**：域名中点号的最小数量



Resolver 会优先使用 **/etc/resolv.conf** 中第一个 **nameserver** 指定的 DNS 服务器来发送 DNS 请求。如果该服务器响应失败（如超时、服务器不可达或返回错误），它会先在同一个服务器上重试几次（由 **options attempts:n** 指定，**默认通常是 2 次**）。只有重试失败后，才会切换到下一个服务器。

Resolver 会向 nameserver 指定的服务器发送 DNS 请求，并在服务器响应 DNS 查询结果后，将结果提供给应用程序。



## systemd-resolved

在许多现代 Linux 发行版中，例如 Ubuntu，**/etc/resolv.conf** 通常指向 **127.0.0.53**，这是一个本地地址。**127.0.0.53** 的 53 端口由 **systemd-resolved** 监听，而 **systemd-resolved** 则是一个后台运行的系统服务（守护进程），专门负责处理 DNS 查询。

其目的是让 **Resolver** 将 **DNS 请求** 发送给 **systemd-resolved**，从而让 **systemd-resolved** 接管处理。



**systemd-resolved** 首先检查自己的 **DNS 缓存记录**，以查看是否已知 **example.com** 的 IP 地址。如果缓存中有记录，它会立即返回结果。如果没有，它会根据配置文件 **/etc/systemd/resolved.conf**，向 **外部 DNS 服务器** 发送查询。

外部 DNS 服务器响应 **DNS 查询结果**后，**systemd-resolved** 会将这条 **DNS 记录**添加到自己的 **DNS 缓存记录**中，并将这个 **DNS 记录**传递给 **Resolver**，然后 **Resolver** 将结果提供给应用程序。



**为什么使用 systemd-resolved？**

- **缓存**：缓存更全面，包括多种DNS记录类型（A、AAAA、CNAME、MX、SRV等）。
- **DNSSEC**：支持验证 DNS 数据的安全性。



本文章**不介绍** systemd-resolved 是如何维护 DNS 服务列表的。