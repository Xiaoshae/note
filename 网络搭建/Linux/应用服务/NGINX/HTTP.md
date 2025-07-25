# HTTP

## 发展历程

注：此章节主要追溯超文本传输协议（HTTP）的起源与演进，重点阐述其发展历程，而非深入探讨具体技术细节。



HTTP（超文本传输协议，HyperText Transfer Protocol）是互联网上用于传输超文本数据（如 HTML 文件、图像、查询结果等）的应用层协议，它是万维网（World Wide Web）的基础协议。



HTTP 的最初设计和实现主要由蒂姆·伯纳斯-李完成。1989 年，他在欧洲核子研究组织（CERN）工作期间，提出了一份名为《Information Management: A Proposal》的提案，描述了一个基于超文本的分布式信息系统。这份提案奠定了万维网、统一资源定位符（URL）、超文本标记语言（HTML）和 HTTP 的基础。伯纳斯-李的目标是创建一个便于科学家们共享研究信息的系统，这最终促成了万维网的诞生。HTTP 作为万维网体系结构中的核心协议，用于在客户端（通常是浏览器）和服务器之间传输超文本数据。

1990 年，伯纳斯-李开发了第一个 Web 服务器和第一个 Web 浏览器（名为 "WorldWideWeb"）。同时，他定义了 HTTP 的最初版本（后来被称为 HTTP/0.9），这是一个非常简单的协议，仅支持 GET 请求，用于获取 HTML 文档。在 HTTP/1.0 之前的版本通常不被视为“正式标准”，而是一个实验性协议。

随着万维网的普及，更多个人、团队和组织参与了 HTTP 的开发和标准化工作。伯纳斯-李后来于 1994 年创立了万维网联盟（W3C）。



1997 年，互联网工程任务组（IETF）发布了 HTTP/1.0（RFC 1945），这是第一个以 RFC 形式发布的 HTTP 标准，因此可以认为是第一个正式的、由 IETF 标准化的 HTTP 版本。

IETF 是一个开放的国际技术社区，任何对互联网技术开发感兴趣的个人、团队或组织都可以参与其标准化工作。IETF 的座右铭是：“我们拒绝国王、总统和投票，我们相信粗略的共识和运行的代码（We reject kings, presidents, and voting; we believe in rough consensus and running code）。

- IETF 没有正式会员限制，无需特定身份、公司背景或学术资格，任何人都可以提交提案。
- IETF 重视提案的技术价值和可行性，而非提交者的身份。

个人开发者、研究人员、公司员工，甚至独立爱好者都可以向 IETF 提交协议草案（称为 Internet-Draft）。许多成功的协议最初都是由个人或小团队提出的。



万维网联盟（W3C）专注于与 HTTP 密切相关的 Web 内容技术，如 HTML、层叠样式表（CSS）和 JavaScript API，并不直接负责 HTTP 协议的标准化。然而，W3C 也参与一些与 HTTP 交互的技术规范，例如 WebSockets（一种基于 HTTP 的协议扩展）或 Web 安全（如跨域资源共享 CORS）。

互联网工程任务组（IETF）负责 HTTP 协议的标准化，包括 HTTP/1.0、HTTP/1.1、HTTP/2 和 HTTP/3。IETF 关注 HTTP 的传输机制（如请求/响应格式、二进制分帧、多路复用）和底层技术细节（如性能优化、安全性）。



HTTP 的发展历程如下：

- **HTTP/0.9（1991 年）**：这是最初的 HTTP 版本，功能非常简单，主要用于在欧洲核子研究组织（CERN）内部传输基本的 HTML 文档。它仅支持 GET 请求，且每次请求后连接就会关闭。
- **HTTP/1.0（1996 年）**：由互联网工程任务组（IETF）发布，这是第一个正式的 HTTP 标准。相较于 0.9 版本，HTTP/1.0 引入了请求头和响应头，并支持除 GET 之外的其他请求方法，如 POST。然而，每次请求-响应结束后连接仍会关闭。
- **HTTP/1.1（1997 年，1999 年更新）**：作为 HTTP/1.0 的重要升级，其正式文档最初为 RFC 2068（1997 年），后更新为 RFC 2616（1999 年）。此版本最显著的改进是引入了持久连接，即在一个 TCP 连接上可以发送多个请求和接收多个响应，显著提升了效率。
- **HTTP/2（2015 年）**：正式文档为 RFC 7540。HTTP/2 旨在解决 HTTP/1.x 在性能方面的瓶颈。它引入了多路复用和头部压缩等核心特性，允许在单个 TCP 连接上同时进行多个请求和响应，显著提升了网页加载速度。
- **HTTP/3（2022 年）**：正式文档为 RFC 9114。HTTP/3 最大的变化是将底层传输协议从 TCP 切换为基于用户数据报协议（UDP）的 QUIC 协议。这一改变旨在解决 TCP 在高丢包率和高延迟网络下的性能问题，进一步提升了连接速度和数据传输效率。



## HTTP

HTTP（Hypertext Transfer Protocol）是一种基于**客户端-服务器**模型的**请求-响应**协议，主要用于在客户端（如Web浏览器）和服务器之间传输超文本文档（如HTML）。

**HTTP/0.9、HTTP/1.0 和 HTTP/1.1** 的消息在 TCP 数据（有效载荷部分）中以**纯文本**形式传输。

**HTTP/2.0** 的消息在 TCP 中以二进制分帧（Binary Framing） 形式传输。

**HTTP/3.0** 采用基于 UDP 的 QUIC 协议，消息通过 QUIC 帧（Frames） 传输。





## HTTP/0.9

HTTP 最早的版本是 HTTP/0.9，于 1991 年由蒂姆·伯纳斯-李（Tim Berners-Lee）在 CERN 开发。

它是一种极其简单的协议，仅支持 GET 方法，没有头部、状态码或版本号，响应仅包含文档内容本身。



**请求格式示例：**

```
GET /path/to/resource
```



**响应格式示例：**

```
<html>
  <body>
    <h1>Hello, World!</h1>
  </body>
</html>
```



## HTTP/1.0

HTTP/1.0 是首个标准化版本，于1996年通过RFC 1945正式发布。



**起始行**：

- **请求行**：格式为 `Method SP Request-URI SP HTTP-Version CRLF`，如 `GET /index.html HTTP/1.0\r\n`。
- **状态行**：格式为 `HTTP-Version SP Status-Code SP Reason-Phrase CRLF`，如 `HTTP/1.0 200 OK\r\n`。

**头部字段**：键值对形式，如 Content-Type: text/html，每行以 CRLF 结束。

**空行**：用 CRLF（\r\n）表示头部结束。

**消息体**：可选，包含实际数据（如 HTML 内容）。



**请求格式示例：**

```
GET /index.html HTTP/1.0\r\n
User-Agent: Mozilla/1.0\r\n
Accept: text/html\r\n
\r\n
```



**响应格式示例**：

```
HTTP/1.0 200 OK\r\n
Content-Type: text/html\r\n
Content-Length: 137\r\n
\r\n
<html>
  <body>
    <h1>Welcome</h1>
  </body>
</html>
```



**HTTP/1.0 的特点**

- **请求方法**：支持 GET、POST 和 HEAD 方法。
- **状态码**：引入了状态码（如 200 OK、404 Not Found）用于指示请求结果。
- **头部字段**：支持基本的头部，如 Content-Type、Content-Length、User-Agent 等，但功能有限。
- **连接管理**：默认每个请求建立一个新的 TCP 连接，完成后关闭（非持久连接）。
- **无主机头**：请求中不包含 Host 头部，限制了虚拟主机的支持。



## HTTP/1.1

HTTP/1.1 是万维网数据通信的基础协议，定义于 RFC 2616（后来更新为 RFC 7230 和 RFC 7231）。

HTTP/1.0 和 HTTP/1.1 在消息格式上基本无变化，新增 `Transfer-Encoding: chunked` 的格式有细微变化。



**HTTP/1.1 特性**：

**持久连接**：`Connection: keep-alive`，允许复用同一连接，显著减少延迟。根据 RFC 7230，持久连接是默认行为，除非显式指定 Connection: close。

**Host 头部**：强制要求 Host 头部（RFC 7230, Section 5.4），支持虚拟主机。

**分块传输编码**： `Transfer-Encoding: chunked（RFC 7230, Section 3.3.1）`，允许服务器动态发送数据，每块以长度前缀开头，最后以零长度块结束。

**范围请求**：**Range** 头部和 206 Partial Content 状态码（RFC 7233），允许客户端请求资源的一部分。

**缓存控制**：**Cache-Control** 头部（RFC 7234），提供更灵活的指令，如 **max-age**、**no-cache**、**must-revalidate**。

**管道化**：允许客户端连续发送多个请求。虽然提高了并发性，但因队头阻塞（Head-of-Line Blocking）问题，实际应用有限。

**新增头部和状态码**：扩展了头部字段（如 Accept-Encoding、ETag）和状态码（如 100 Continue、206 Partial Content）。

**内容压缩**：通过 **Accept-Encoding** 和 **Content-Encoding** 协商压缩（如 gzip、deflate）。



### 持久连接

HTTP/1.0 默认采用**非持久连接**。每个 HTTP 请求-响应对都需要建立一个新的 TCP 连接，完成后立即关闭。

1. 客户端发起 TCP 三次握手，建立连接。
2. 发送 HTTP 请求（如 GET /index.html HTTP/1.0）。
3. 服务器响应（如 HTTP/1.0 200 OK）。
4. 连接关闭（TCP 四次挥手）。



HTTP/1.1 引入了**持久连接**（Persistent Connections），也称为 **Keep-Alive**。默认情况下，TCP 连接在**第一个 HTTP 请求（请求-响应）结束**后仍保持打开，允许在同一 TCP 连接上处理多个 HTTP 请求。

客户端和服务器通过 **Connection** 头部控制连接行为：

- `Connection: keep-alive`：显式请求保持连接（HTTP/1.1 默认行为）。
- `Connection: close`：指示在响应后关闭连接。



HTTP/1.1 客户端默认会假定连接是持久的，它在请求中发送 **Connection: Keep-Alive**。

如果**已建立持久连接**，**客户端**想关闭连接，它在请求中发送 **Connection: close**。

如果**服务端**想关闭连接（**拒绝建立持久连接**或**关闭已建立的持久连接**），它在响应中发送 **Connection: close**。



服务器或客户端可通过**超时**或**最大请求数限制**连接的存活时间。

- **超时管理**：服务器通常设置超时（例如 5-15 秒）以关闭空闲连接，避免资源浪费。

- **最大请求数**：服务器可能限制单一连接处理的请求数量（如 100 个），以平衡负载。



**HTTP 1.1 持久化连接**，只有在收到前一个响应后，客户端才能在同一连接上发送下一个请求。

```
GET /index.html HTTP/1.1\r\n
Host: example.com\r\n
Connection: keep-alive\r\n
\r\n
---
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
Content-Length: 137\r\n
\r\n
<html>...</html>
---
GET /style.css HTTP/1.1\r\n
Host: example.com\r\n
Connection: keep-alive\r\n
\r\n
---
HTTP/1.1 200 OK\r\n
Content-Type: text/css\r\n
Content-Length: 50\r\n
\r\n
body { color: blue; }
```



### 管道化

管道化（Pipelining）是 HTTP/1.1 引入的一项可选特性，允许客户端在收到前一个请求的响应之前，连续发送多个请求到同一 TCP 连接。管道化依赖持久连接，旨在进一步减少延迟。



客户端在持久连接上连续发送多个请求，无需等待响应。服务器必须**按请求接收的顺序返回响应**（FIFO，先进先出）。

请求方法必须是“安全的”（如 GET、HEAD），因为非幂等方法（如 POST）可能导致不可预测的结果。

客户端和服务器必须正确处理消息体长度（通过 Content-Length 或 Transfer-Encoding: chunked）。



如果第一个请求的处理时间较长（如服务器处理复杂查询），后续请求的响应会被延迟。

例如，若 `/index.html` 的响应延迟 500ms，则 `/style.css` 和 `/script.js` 的响应也会被阻塞。

根据 MDN Web Docs，队头阻塞是管道化的主要限制，导致其未被广泛采用。



现代浏览器**默认支持 HTTP/1.1 的持久连接**，但**基本不支持管道化**，因管道化存在队头阻塞和兼容性问题。**队头阻塞**在持久连接和管道化中均存在，但管道化的阻塞问题更严重，因其要求严格的请求-响应顺序。

浏览器通过并行 TCP 连接（每个域名 6-8 个）或升级到 HTTP/2/HTTP/3 来优化性能，替代管道化。