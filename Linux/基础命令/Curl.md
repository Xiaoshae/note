# Curl

curl 是一种利用 URL  从服务器传输数据或向服务器传输数据的工具。它支持以下协议：DICT、FILE、FTP、FTPS、GOPHER、GOPHERS、HTTP、HTTPS、IMAP、IMAPS、LDAP、LDAPS、MQTT、POP3、POP3S、RTMP、RTMPS、RTSP、SCP、SFTP、SMB、SMBS、SMTP、SMTPS、TELNET、TFTP、WS 和 WSS。



curl 的所有传输相关功能均由 libcurl 提供支持。详情请参阅 libcurl。



## URL

URL 的语法依赖于协议。您可以在 RFC 3986 中找到详细说明。



如果你提供的 URL 没有带开头的协议方案（protocol://），curl 会尝试**猜测**你想要的协议。

它会**默认使用 HTTP**，但同时会根据常用主机名前缀来推测其他协议。例如：

- 如果主机名以 ftp. 开头，curl 会自动假定你想使用 **FTP** 协议；
- 以 **dict.** 开头 → 猜 **DICT**；
- 以 **ldap.** 开头 → 猜 **LDAP**；
- 以 **imap.、pop3.、smtp.** 开头 → 分别猜对应的邮件协议，等等。



 **示例：**

```
file.txt    						 # 自动使用 FTP 协议
curl http://example.com              # 明确是 HTTP
curl example.com                     # 没写协议 → 默认用 HTTP
curl ftp.gateway.com/bigfile
```



命令行中，凡是**不是选项或选项参数**的东西，curl 都会默认当作 URL 来处理。



curl 在执行多次传输（multiple transfers）时，会尽量**复用已建立的连接**，这样从同一个服务器下载多个文件时，就不会为每个文件都重新建立连接和进行握手，从而显著提升速度。

**连接复用仅限于同一次命令行调用中指定的多个 URL**，不同次独立的 curl 命令运行之间无法实现连接复用。



## output

curl 本身对传输的内容完全不解析、不理解。它只是忠实地把服务器发来的字节原样传递（或保存），不会自动做任何编码、解码、格式转换之类的处理——除非你用专门的选项明确要求它这么做（比如 --data-urlencode、-u 解码等）。



如果不特别指定，curl 会把接收到的数据直接输出到标准输出（stdout，也就是屏幕）。

你可以通过以下选项让它改为保存到本地文件：

- **-o / --output**：指定保存路径和文件名
- **-O / --remote-name**：直接使用 URL 中原始的文件名保存



如果在同一行中列出了多个 URL，必须为**每一个** URL 显式地指定 `-o`（小写 output）参数。

假设你要同时下载两张图片：

1. 第一张图：`http://example.com/a.jpg` → 想保存为 **`photo_1.jpg`**
2. 第二张图：`http://example.com/b.png` → 想保存为 **`image_2.png`**



正确的命令格式

```
curl http://example.com/a.jpg -o photo_1.jpg http://example.com/b.png -o image_2.png
```



或者写作更清晰的配对形式（`curl` 并不强制 URL 在前或参数在前，但**配对**必须正确）：

```
curl -o photo_1.jpg http://example.com/a.jpg -o image_2.png http://example.com/b.png
```



`curl` 会将第一个 `-o filename` 应用于它遇到的第一个 URL，将第二个 `-o filename` 应用于第二个 URL，以此类推。

如果你只写一个 `-o`，或者试图把所有文件名写在最后，会导致错误或覆盖。



## 进度条

curl 在传输时默认会显示一个**进度条/进度表**，内容包括： from 已传输数据量、当前速度、预计剩余时间等信息。

- 速度单位以**每秒字节数**显示。

- 使用的单位后缀是基于 **1024** 的（而不是1000）：

  - k = KiB = 1024 bytes

  - M = MiB = 1024×1024 = 1,048,576 bytes

  - G = GiB, T = TiB, P = PiB, E = EiB 

    （严格来说这些应该是 kibibyte、mebibyte 等，但日常大家都直接说 “k”、“M”）



在 Linux/Unix 终端中，有两个主要的信息流：

- **标准输出 (stdout)：** 用于显示实际的数据（例如服务器返回的 "Upload Successful" 或者 JSON 数据）。
- **标准错误 (stderr)：** 通常用于显示状态信息、报错、以及**进度条**。



**curl** 的默认逻辑为，当发起 **POST/PUT 请求**时，服务器通常会返回一段响应内容（比如 API 的 JSON 结果）。curl 默认会将这段内容直接打印到终端屏幕上（stdout）。 为了避免进度条的刷新字符和服务器返回的 JSON 文本混在一起变成乱码，curl 会智能地关闭进度条显示。



**重定向标准输出**

为了激活 curl 的进度统计显示，需将**标准输出（stdout）重定向至文件或空设备（/dev/null）**。

```
curl -X POST -T bigfile.iso http://example.com/upload > output.txt
```

**（注意末尾的 > output.txt）**



显式指定文件描述符，此处 `1>` 与 `>` 等价（1 代表标准输出的文件描述符）。但在使用 `1>` 时，数字 `1` 与符号 `>` 之间**严禁包含空格**。

```
curl -X POST -T bigfile.iso http://example.com/upload 1> output.txt
```



如果你既想看屏幕上的返回结果，又想强行看进度条（不介意格式可能乱掉），可以使用 `-v` (verbose) 或者专门的参数。



curl 检测到接收到的内容是二进制数据（例如图片、可执行程序或压缩文件），且当前的标准输出是指向终端屏幕的，它会拒绝将二进制数据打印到屏幕上，以防破坏终端的显示状态。

必须使用 `-o <file>` 或 `-O` 将数据保存到文件。



## Options

选项以一个或两个破折号开头。许多选项在其后面需要跟一个附加值。如果提供的文本不是以破折号开头，则会被视为 URL 并按 URL 处理。

- **短选项（单破折号形式）**，例如 **-d**，在其与取值之间可以有空格，也可以没有空格，但**推荐使用空格分隔**。 长选项（双破折号形式），例如 --data，则**必须**在选项和取值之间使用空格。
- **长选项（双破折号形式）**，例如 **--data**，则必须在选项和取值之间使用空格。



不需要附加值的短选项可以紧挨着写在一起，例如你可以一次性写 -O、-L 和 -v 为 -OLv。

一般来说，所有布尔型选项使用 --option 表示启用，再使用 --no-option 表示禁用。也就是说，使用相同的选项名，但加上 no- 前缀。不过，在本列表中我们主要只列出并展示 --option 这种形式。



命令行中第一个完全是两个破折号（--）的参数，表示选项结束；在此之后的任何参数，即使以破折号开头，也会被当作 URL 处理。

当使用 --next 时，它会重置解析器状态，你会重新开始一个干净的选项状态，但全局选项除外。全局选项在 --next 之后仍然保留其值和含义。



curl 对命令行参数的内容几乎不做验证。如果传入“奇葩字符”（比如换行符等特殊八位字节），可能会引发意料之外的行为。

以下选项属于**全局选项**（global）： **--fail-early, --libcurl, --parallel-immediate, --parallel-max-host, --parallel-max, --parallel, --progress-bar, --rate, --show-error, --stderr, --styled-output, --trace-ascii, --trace-config, --trace-ids, --trace-time, --trace, --verbose**



## HTTP

关于 **curl** 在进行 HTTP 协议请求时默认行为的详细介绍。



**请求方法 (Request Method)**

与 HTTP 服务器通信时，`curl` 默认使用 **GET** 方法，只有在使用特定选项（如 `-d` 发送数据）时，它才会自动切换为 POST 。



**重定向处理 (Redirects)**

默认情况下，如果服务器返回重定向响应（即 3XX 响应代码和 Location 头），`curl` **不会**自动跟随跳转到新的位置 。

必须使用 `-L` 或 `--location` 选项才能让 `curl` 重做请求到新的位置 。



**错误处理 (Error Handling)**

默认情况下，curl 不认为 HTTP 错误响应代码（如 404 Not Found 或 500 Internal Server Error）是传输失败 。

它会像处理正常页面一样，输出服务器返回的错误正文内容 。若要让 curl 在遇到此类错误时失败并返回退出代码 22，需使用 **-f (--fail)** 选项 。



**安全性验证 (TLS/HTTPS)**

当使用 HTTPS 等安全协议时，`curl` 默认会验证连接的安全性 。

它会验证服务器的 TLS 证书是否包含与 URL 中主机名匹配的名称，并确认证书是否由受信任的 CA（证书颁发机构）签名。



**请求头 (Headers)**

`curl` 会发送包含自身版本号的 `User-Agent` 字符串，格式通常为 `curl/VERSION`（例如 `User-Agent: curl/8.18.0`） 

`curl` 默认在 TCP 连接上启用 Keep-Alive 消息 。

在一次命令行调用中指定多个 URL 时，`curl` 会尝试复用连接，以避免多次握手，从而提高速度 。



### 认证

curl 支持多种 HTTP 认证协议：

- Basic：HTTP 标准认证，以明文（Base64编码）发送凭据，默认方式。
- Digest：摘要认证，避免以明文发送密码，比 Basic 更安全。
- NTLM：微软专有的认证协议，主要用于 IIS 服务器。
- Negotiate (SPNEGO)：启用 GSS-API 或 SSPI 支持的认证，通常用于 Kerberos。
- AWS SigV4：用于 AWS API 请求的签名认证。
- OAuth 2.0 Bearer Token：使用 Bearer 令牌进行认证。



**--basic**

Basic 认证是默认的认证方式。它以明文（Base64 编码）发送用户名和密码。

这是 `curl` 的默认行为。通常用于覆盖之前设置的其他认证选项（例如，如果你在别处设置了 `--digest`，可以用此选项改回 Basic）。



**--digest**

Digest 认证通过哈希算法进行通信，避免了密码在网络上以明文形式传输，比 Basic 更安全。

启用 HTTP Digest 认证 。



**`-u, --user <user:password>`**

无论选择 Basic 还是 Digest，都需要通过这个选项提供具体的用户名和密码。

如果在 Digest 认证中使用，`curl` 会自动处理哈希计算。

如果只提供用户名（如 `-u user`），`curl` 会在终端提示输入密码 。



### 代理

curl 支持多种代理协议，不同的协议前缀决定了 curl 如何与代理交互以及由谁来解析域名。

**HTTP/HTTPS 代理**：

- **http://**：标准的 HTTP 代理。
- **https://**：HTTPS 代理，即 curl 与代理服务器之间的连接是加密的（TLS）。

**SOCKS 代理**：

- **socks4://**：SOCKS4 协议。
- **socks4a://**：SOCKS4a 协议，允许由代理服务器解析主机名。
- **socks5://**：SOCKS5 协议，默认由本地解析主机名。
- **socks5h://**：SOCKS5 协议，强制由代理服务器解析主机名。



**指定代理服务器**

主要使用 **-x** 或 **--proxy** 选项，格式为 **`[protocol://][username]:[password]@host[:port]`** 。

- 如果未指定协议前缀，默认视为 **HTTP** 代理 。
- 如果未指定端口，默认为 **1080** 。
- 用户名和密码是可选的。



**代理认证机制**

**-U** 或 **--proxy-user <user:password**> 传入用户名和密码 。

- 也可以在代理 URL 中直接包含凭证（会被 URL 解码）。
- 为了安全，可以只提供用户名（如 `-U user`），curl 会提示输入密码 。



**HTTP/HTTPS 代理认证协议**

- **Basic**：默认方式 。可通过 **--proxy-basic** 显式指定 。
- **Digest**：通过 **--proxy-digest** 启用 。



**HTTPS 代理的安全配置 (TLS)**

当使用 `https://` 前缀的代理时，curl 与代理之间的通信是加密的。curl 提供了一套完整的 `--proxy-*` 选项来控制这一层的安全性，其功能与访问 HTTPS 目标服务器的选项对等。

**证书验证**：

- **--proxy-cacert**：指定验证代理服务器用的 CA 证书文件 。
- **--proxy-capath**：指定 CA 证书目录 。
- **--proxy-ca-native**：使用操作系统的原生 CA 存储 。
- **--proxy-insecure**：跳过代理证书验证（不安全）。
- **--proxy-crlfile**：指定证书吊销列表 。
- **--proxy-pinnedpubkey**：锁定代理的公钥指纹，防止中间人攻击 。



**客户端认证（双向 SSL）**：

如果代理要求客户端证书，可用 **--proxy-cert** 指定**证书** ，**--proxy-key** 指定**私钥** ，以及 **--proxy-pass** 提供**私钥密码**。



**协议与加密套件**：

- **--proxy-tlsv1**：强制使用 TLS 1.x 或更高版本 。
- **--proxy-ciphers**：指定 TLS 1.2 及以下的加密套件 。
- **--proxy-tls13-ciphers**：指定 TLS 1.3 的加密套件 。
- **--proxy-http2**：尝试与代理协商 HTTP/2 协议 。



**隧道与高级控制**

**HTTP 隧道 (CONNECT)：**

使用 **-p** 或 **--proxytunnel** 选项。这会让 **curl** 发送 **HTTP CONNECT** 请求给代理，建立直通远程目标的隧道。这在通过 HTTP 代理访问 HTTPS 站点时是必须的，也常用于绕过代理的协议限制 。



**头部控制：**

- **--proxy-header**：向代理发送自定义的 HTTP 头（例如自定义认证头），这些头不会发给远程目标服务器 。
- **--suppress-connect-headers**：在输出中隐藏代理建立隧道时产生的 CONNECT 响应头 。



**排除代理**：

使用 **--noproxy** 选项指定不走代理的主机列表（支持通配符 `*` 和 CIDR IP 段）。若设为 `*` 则禁用所有代理 。



### dns

在默认情况下，curl 使用系统默认的名称解析机制来将主机名解析为 IP 地址 。这意味着它通常依赖于操作系统配置的 DNS 解析器（例如 `/etc/resolv.conf` 或系统的 hosts 文件）。

curl 在进行解析时，如果未指定特定的 IP 版本限制，通常会同时尝试 IPv4 和 IPv6 地址。为了优化双栈环境下的连接速度，curl 默认采用 "Happy Eyeballs" 算法，即给 IPv6 一个微小的领先时间（默认 200 毫秒），如果在该时间内无法连接，则并行尝试 IPv4 连接，并使用最先建立的那个连接 。



**自定义 DNS 解析服务器**

用户可以通过 `--dns-servers` 选项指定自定义的 DNS 服务器列表来替代系统默认设置。

curl 会在本地连接目标服务器完成 dns 解析。



**HTTP 代理**

如果使用的是标准 HTTP 代理（即默认的 `-x` 或 `--proxy` 行为），curl 会将包含主机名的完整 URL 发送给代理服务器，这意味着 DNS 解析实际上是由代理服务器完成的，curl 本身并不解析目标主机名 。



**SOCKS 代理**

当使用 **SOCKS4** 或 **SOCKS5** 代理协议时，curl 默认会在本地解析主机名，然后将解析后的 IP 地址传递给代理服务器 。



当使用 `socks4a` 或 `socks5h`时，curl 的行为是将主机名解析的职责完全移交给代理服务器。



原始的 **SOCKS4 协议**设计要求客户端必须在建立连接（CONNECT）请求中提供目标主机的 **IP 地址**（IPv4）。客户端必须在本地先将域名解析为 IP 地址，然后将该 IP 发送给代理服务器。

为了解决本地无法解析域名的问题，SOCKS4 协议有一个名为 **SOCKS4a** 的扩展。在 SOCKS4a 中，客户端可以将目标 IP 设置为一个特殊的无效地址（如 `0.0.0.x`），并在数据包末尾附加**域名**字符串。代理服务器读取到这个特殊 IP 后，会使用附加的域名进行解析。



**SOCKS5** 协议在设计时就更加灵活。在请求包中有一个“地址类型”（ATYP）字段。

- 如果客户端想要发送 IP，它将 ATYP 设置为 `0x01` (IPv4) 或 `0x04` (IPv6)。
- 如果客户端想要发送域名，它将 ATYP 设置为 **`0x03` (DOMAINNAME)**，即**可以直接指定域名**。



虽然 **SOCKS5** 协议支持，但客户端软件可以选择是否通过代理服务器进行域名解析。使用标准的 **--socks5** 或 **socks5://** 时，curl 默认会在本地解析主机名，然后将 IP 发送给代理（即使用 ATYP 0x01 或 0x04）。

- 若要强制使用域名（即使用 ATYP 0x03），必须使用 **--socks5-hostname** 选项或 **socks5h://** 协议前缀，这会让 curl 将主机名原样发送给代理服务器进行解析 。



**DOH 解析**

`--doh-url` 选项提供了一种通过 HTTPS 协议进行远程 DNS 解析的机制（DNS-over-HTTPS）。

该选项接受一个 HTTPS URL 作为参数，指定用于解析主机名的 DoH 服务器，从而绕过系统默认的名称解析机制。当配置了代理服务器时，DoH 请求本身（即为了解析目标域名而发出的 HTTPS 请求）会被视为普通的 HTTPS 流量。根据 curl 的工作机制，DoH 流量会经过代理服务器的网络发送，而不是直接通过本地网络发送。



如果 HTTPS URL 是域名而非 IP，在使用 DoH 功能之前，curl 必须先解析 DoH 服务器自身的主机名（例如 `doh.example.com`）以建立连接。对于这个特定的“引导性”DNS 查询，文档明确指出默认情况下会绕过 DoH 机制 。curl 默认会使用系统解析器来解析 DoH 服务器的主机名（以避免死循环）。

用户可以使用 `--resolve` 选项来手动指定 DoH 服务器的 IP 地址以避免这一初始查询 。



如果 HTTPS URL 使用的是 IP 地址，则不存在“引导性”DNS 查询。







