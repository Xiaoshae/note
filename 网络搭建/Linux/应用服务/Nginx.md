# NGINX

NGINX使用**文本格式的配置文件**来定义其行为，默认配置文件名为 **nginx.conf**，通常位于以下路径：

**NGINX 开源版**（根据安装方式和操作系统，可能是以下之一）

- **/etc/nginx/nginx.conf**
- **/usr/local/etc/nginx/nginx.conf**
- **/usr/local/nginx/conf/nginx.conf**



## 配置文件结构

配置文件由**指令（directives）**组成。



### 指令

**简单指令**：单行指令，以分号（**;**）结尾，例如：

```nginx
user nobody;
error_log logs/error.log notice;
worker_processes 1;
```



**容器指令（块）**：包含其他指令，用大括号（{}）包裹，例如 **http** 或 **server** 块。

```nginx
http {
    # HTTP 相关配置
}
```



### 上下文

上下文是 NGINX 配置文件的顶层结构，用于分组处理不同类型的流量。主要的上下文包括：

- **main**：全局配置，位于任何块之外的指令，例如 user nobody;。
- **events**：处理通用连接设置，例如连接池大小。
- **http**：处理 HTTP 流量。
- **mail**：处理邮件流量。
- **stream**：处理 TCP/UDP 流量。

```nginx
user nobody; # main 上下文

events {
    # 连接处理配置
}

http {
    # HTTP 相关配置
}

stream {
    # TCP/UDP 相关配置
}
```



### 虚拟服务器

在 http、mail 或 stream 上下文中，可以定义一个或多个 **server 块**，每个 server 块代表一个虚拟服务器，用于处理特定流量：

- **HTTP 流量**：server 块定义域名或 IP 地址的请求处理，内部可以包含 location 块来处理特定的 URI。
- **Mail 或 Stream 流量**：server 块定义监听的 TCP 端口或 UNIX 套接字。

```nginx
http {
    server {
        listen 80; # 监听 80 端口
        server_name example.com; # 域名
        location /one {
            # 处理以 /one 开头的 URI
        }
        location /two {
            # 处理以 /two 开头的 URI
        }
    }
    server {
        listen 8080; # 另一个虚拟服务器
        server_name another.com;
    }
}

stream {
    server {
        listen 12345; # 监听 TCP 端口 12345
        # TCP 虚拟服务器配置
    }
}
```



### 继承

- 子上下文会**继承**父上下文的指令设置。
- 如果子上下文中重新定义了相同的指令，则会**覆盖**父上下文的设置。

```nginx
http {
    keepalive_timeout 65s; # 父上下文：设置默认超时

    server {
        listen 80;
        server_name example.com; # 子上下文：继承 65s 超时

        location / {
            root /usr/share/nginx/html;
            # ...
        }
    }

    server {
        listen 80;
        server_name api.example.com;

        keepalive_timeout 30s; # 子上下文：覆盖为 30s 超时
        # ...

        location / {
            proxy_pass http://backend;
            # ...
        }
    }
}

```



### include

为了便于维护，建议将配置文件拆分为多个**功能特定的文件**，存储在 **/etc/nginx/conf.d** 目录下，并在主 **nginx.conf** 文件中使用 **include 指令**引用这些文件。

```nginx
# 主配置文件 /etc/nginx/nginx.conf
include conf.d/http;          # HTTP 相关配置
include conf.d/stream;        # TCP/UDP 相关配置
include conf.d/exchange-enhanced; # 其他功能配置
```



### 重载配置文件

更改配置文件后，需要**重新加载**才能生效。NGINX 支持以下两种方式：

**重启 NGINX 进程**

停止并重新启动 NGINX 服务。



**发送 reload 信号**

不中断当前请求，平滑加载新配置。

```
nginx -s reload
```





## Web 服务

从宏观上看，配置 NGINX 作为 Web 服务器的核心任务是定义其处理的 URL 以及如何处理这些 URL 对应的 HTTP 请求。从微观层面来看，配置需要**定义一组虚拟服务器（server）**，用于**控制特定 Domain或 IP 地址的请求处理**。

每个处理 HTTP 流量的**虚拟服务器（server）**通过称为**位置（location）**的配置单元，控制**特定 URI 集合的处理方式**。

**Location** 可以选择将请求**代理到后端服务器、返回本地文件、修改 URI 以重定向到其他 Location 或虚拟服务器（server）**，甚至返回特定的错误码，并可为每个错误码配置对应的自定义页面。



**NGINX** 的配置文件（通常是 **nginx.conf**）采用分层结构，主要涉及以下几个层级：

```text
http
  └── server
        └── location
```

- **http 块**：作为 HTTP 服务的全局配置容器，**包含所有虚拟服务器（server 块）和全局 HTTP 设置。**
- **server 块**：定义一个虚拟服务器，**处理特定的域名（server_name）或 IP 地址的请求**。每个 server 块可以包含多个 location 块。
- **location 块**：位于 server 块内部，定义**如何处理匹配特定 URI 模式的请求**，是 NGINX 配置中最细粒度的控制单元。



### 设置虚拟服务器

NGINX 的配置文件必须至少包含一个 **server** 指令，以**定义一个虚拟服务器**。NGINX 在处理请求时，首先会选择**负责该请求的虚拟服务器**。

虚拟服务器通过 **http** 上下文中的 **server** 指令定义，例如：

```nginx
http {
    server {
        # 服务器配置
    }
}
```



在 http 上下文中可添加多个 server 指令，以定义多个虚拟服务器。

```nginx
http {
    server {
        # 服务器配置 1
    }
    
    server {
        # 服务器配置 2
    }
}
```



### listen

server 配置块通常包含 listen 指令，用于指定服务器监听的 IP 地址和端口（或 Unix 域套接字及路径）。

若省略端口，则使用标准端口；若省略地址，则服务器监听所有地址。若未包含 listen 指令，默认端口根据超级用户权限分别为 80/tcp 或 8000/tcp。

支持 IPv4 和 IPv6 地址，IPv6 地址需用方括号括起来。例如，以下配置定义了一个监听 IP 地址 127.0.0.1 和端口 8080 的服务器：

```nginx
server {
    listen 127.0.0.1:8080;
    # 其他服务器配置
}
```





当多个服务器匹配请求的 IP 地址和端口时，NGINX 会将请求的 Host 头部字段与 server_name 指令进行比对。

server_name 参数可以是。通配符以星号（*）开头、结尾或两者皆有，星号匹配任意字符序列。正则表达式使用 Perl 语法，需以波浪号（~）开头。例如



**server_name** 参数支持以下语法：

- **完整（精确）**名称：**example.org**
- **前**通配符：**\*.example.org**
- **后**通配符：**www.example.\***
- **前后**通配符：**\*.example.\***
- **Perl 正则表达式**：



若多个名称匹配 **Host** 头部，NGINX 按以下优先级选择匹配项：

1. 精确名称
2. 以星号开头的最大通配符，如 **\*.example.org**
3. 以星号结尾的最大通配符，如 **mail.\***
4. 按配置文件中出现顺序的首个匹配正则表达式



### IP PORT

当多个服务器匹配请求的 IP 地址和端口时，不同 IP 和端口组合的 location 块完全隔离。

```nginx
server {
    listen 0.0.0.0:80;
    server_name xiaoshae.cn;

    location / {
        return 200 "server2";
    }
}

server {
    listen 127.0.0.1:80;

    location / {
        return 200 "server2\n";
    }
}
```



当目标 IP 为 127.0.0.1 时，不可能与 server 0.0.0.0 匹配。

```
curl http://127.0.0.1
server2
```



即使设置 Host 为 xiaoshae.cn 也不会与 server 0.0.0.0 匹配。

```
curl http://127.0.0.1 -H "host: xiaoshae.cn" 
server2
```



### server_name

`server_name` 用于指定虚拟主机（server block）所处理的请求的**域名**。

当多个 server block 监听相同的 **IP 和端口** 时，Nginx 会根据 `server_name` 来匹配并选择对应的 server block 处理请求。



server_name 支持指定多个域名，域名可以是**完整（精确）名称、通配符或正则表达式**，

若 Host 头部**匹配多个 server_name 中指定的域名**，NGINX 按以下优先级选择匹配项（server block）：

1. 精确名称，如：
2. 以星号开头的最大通配符，如 *.example.org
3. 以星号结尾的最大通配符，如 mail.*
4. 配置文件中出现的首个正则表达式。



正则表达式，以 `~`（大小写敏感）或 `~*`（大小写不敏感）开头：

```
server_name ~^www\d+\.example\.com$; # 匹配 www1.example.com, www123.example.com
server_name ~* .+\.example\.com$;     # 大小写不敏感匹配任意子域名
```



示例：

```nginx
server { # server1
    server_name *.example.com;
}

server { # server2
    server_name example.com www.example.com;
}

server { # server3
    server_name mail.*;
}

server { # server4
    server_name ~^www\d+\.example\.com$;  # 匹配 www1.example.com, www123.example.com
}

server { # server5
    server_name ~* .+\.example\.net$;  # 大小写不敏感匹配任意子域名（如 FOO.example.net）
}
```

1. `example.com`、`www.example.com`  匹配 server2
2. `test.example.com`、`hello.example.com` 匹配 server1
3. `www1.example.com`、`www123.example.com` 匹配 server4
4. `FOO.example.net`、`test.example.net` 匹配 server5



### default_server

如果请求的 **Host 头部** 未匹配任何 `server_name` 中定义的域名，Nginx 会使用**默认的 server block** 来处理请求。默认服务器可以是：

- **nginx.conf 文件中第一个出现的 server block**（按配置顺序）；
- 或者通过 `listen` 指令显式标记为 `default_server` 的 server block。



在 `server_name` 的示例中，当请求的 `Host` 头为 `baidu.com`、`google.com` 等未匹配任何 `server_name` 的域名时，Nginx 会默认匹配 `server1`（即第一个 `server` 块）。



在如下示例中，当请求的 `Host` 头为 `baidu.com`、`google.com` 等未匹配任何 `server_name` 的域名时，Nginx 会匹配 `server2`（`default_server` 指定 `server` 块）。

```
server { # server1
    server_name *.example.com;
}

server { # server2
    listen 0.0.0.0:80 default_server;
    server_name example.com www.example.com;
}

...
```



### location

location 指令可根据请求的 URI 将流量发送到不同的代理服务器或提供不同的本地文件。在每个 location 块内，通常可以嵌套更多 location 指令，以进一步精细化特定请求的处理逻辑。

例如，可定义三个 location 块，分别将部分请求发送到某个代理服务器、另一部分发送到其他代理服务器，其余请求则从本地文件系统提供文件。



location 指令的参数有三种类型：**精确匹配、前缀字符串（路径名）和正则表达式**。

**精确匹配**要求请求的 **URI** 必须与指定的 **URL** 完全一致。

例如，以下 location **仅匹配等于 ``/some/path/`` 的请求 URL**。

```nginx
location = /some/path/ {
    # ...
}
```



**前缀字符串**要求请求 URI 以指定的路径开头。

例如，以下 location 匹配以 /some/path/ 开头的请求 URI（如 /some/path/document.html），但不会匹配 /my-site/some/path（因为 /some/path 未出现在 URI 开头）：

```nginx
location /some/path/ {
    # ...
}
```



**正则表达式**以波浪号（~）表示大小写敏感匹配，或以波浪号加星号（~*）表示大小写不敏感匹配。

以下示例匹配包含 **.html** 或 **.htm** 的 URI：

```nginx
location ~ \.html? {
    # ...
}
```



NGINX location 指令不同类型的优先级：

1. `location = ` 定义的**精确匹配**
2. 带有 ^~（尖号波浪号）修饰符的**前缀字符串**
3. **首个匹配的正则表达式**
4. **最长前缀字**符串。



location 上下文可包含指令，指定如何处理请求——提供静态文件或将请求传递给代理服务器。

以下示例中，匹配第一个 location 的请求从 /data 目录提供文件，匹配第二个 location 的请求则传递给代理服务器 `http://www.example.com`：

```nginx
server {
    location /images/ {
        root /data;
    }

    location / {
        proxy_pass http://www.example.com;
    }
}
```

root 指令指定搜索静态文件的文件系统路径，请求 URI 将追加到该路径后形成完整文件名。例如，请求 `/images/example.png` 将返回 `/data/images/example.png` 文件。

**proxy_pass** 指令将请求传递给配置的代理服务器 URL，代理服务器的响应随后返回给客户端。上述示例中，所有不以 `/images/` 开头的请求都传递给代理服务器。



### 使用变量

在配置文件中，可使用变量根据运行时条件动态处理请求。变量是以 $（美元符号）开头的命名值，在运行时计算并作为指令参数使用。变量反映 NGINX 的状态信息，例如当前请求的属性。

NGINX 提供多种预定义变量（如核心 HTTP 变量），也可通过 **set**、**map** 和 **geo** 指令定义自定义变量。大多数变量在运行时计算，包含与特定请求相关的信息。例如，**$host** 表示当前 HTTP 请求中的 host 值，**$remote_addr** 表示客户端 **IP 地址**，**$uri** 表示当前 **URI 值**。



### 返回特定状态码

某些网站 URI 需要立即返回特定的错误或重定向状态码，例如页面临时或永久移动时。最简单的方法是使用 return 指令。例如：

```nginx
location /wrong/url {
    return 404;
}
```



return 的第一个参数是状态码，可选的第二个参数可以是重定向的 URL（适用于 301、302、303 和 307 状态码）或响应体的文本。例如：

```nginx
location /permanently/moved/url {
    return 301 http://www.example.com/moved/here;
}
```



在 **NGINX** 中，变量几乎可以在任何地方使用。例如，在 **`return`** 指令中结合 **`$host`** 和 **`$request_uri`** 变量，可以轻松实现从 **HTTP** 到 **HTTPS** 的重定向。

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name www.example.com;

    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name www.example.com;
    
    ...
}
```



**return** 指令可用于 **location** 和 **server** 上下文。



### 重写请求 URI

rewrite 指令用于在 NGINX 处理请求时，根据指定的正则表达式匹配请求的 URI，并将其替换为新的 URI，或触发重定向（如 301 或 302）。

```nginx
rewrite [正则表达式] [替换后的URI] [标志];
```

**正则表达式**：用于匹配请求的 URI（通常是 $uri 变量的值），基于 Perl 兼容正则表达式（PCRE）。正则表达式可以包含捕获组（如 (.*)），捕获的内容可用于替换后的 URI。

**替换后的 URI**：匹配成功后，请求 URI 将被替换为该值。可以使用**捕获组（如 $1、$2）**引用正则表达式中的匹配内容。

**标志**（可选）：控制 **rewrite** 的行为，常见标志包括：

- **last**：停止当前上下文的 **rewrite** 指令处理，触发新 **URI** 的 **location** 匹配。
- **break**：停止当前上下文的 **rewrite** 指令处理，且不触发新 **URI** 的 **location** 匹配。
- **redirect**：返回 302 临时重定向。
- **permanent**：返回 301 永久重定向。



**示例**

```nginx
rewrite ^/users/(.*)$ /show?user=$1 break;
```

此示例将 **/users/john** 重写为 **/show?user=john**，并使用 **break** 标志停止进一步的重写处理。



**匹配流程**

1. **请求到达 NGINX**

当客户端发送 HTTP 请求（如 GET /users/john），NGINX 首先解析请求的 IP 地址、端口和 Host 头部，选择匹配的虚拟服务器（server 块）。



2. **server 上下文中的 rewrite 指令**

一旦选择了一个 **server** 块，NGINX 会**按顺序执行**该块内的所有 **rewrite** 指令（如果存在）。这些指令在 location 匹配之前运行，适用于对请求 URI 的全局性修改。



**根据标志决定后续行为**

**如果标志为 break**

NGINX 跳过 server 中其他 rewrite 指令，且该请求跳过 location 块匹配。

- 尝试当前 server 上下文中处理重写后的 URI，通常是将 URI 解析为文件路径（如果 server 块定义了 root 指令）或执行其他非 rewrite 指令（如 return 或 try_files）。
- 如果 server 块没有定义处理逻辑（例如没有 root 或其他指令），NGINX 通常返回 404 Not Found。



**如果标志为 last**

停止当前上下文中（此处为 server 上下文）的所有 rewrite 指令的处理。当前 server 块中的所有 location 块中寻找最匹配的新 URI 的 location。



**如果标志为 redirect 或 permanent**

NGINX 立即返回 302 或 301 重定向响应，请求处理终止。



3. **选择 location 上下文**

在 server 上下文的 rewrite 指令执行后（或无 rewrite 指令），NGINX 根据当前 URI（可能已被重写）选择最匹配的 location 块。



**注：如果 server 中执行 rewrite 指令，且标志位为 break，则不会进入该步骤（该请求处理已经终止，已经发送响应数据包）。**



4. **执行 location 上下文中的 rewrite 指令**

在选定的 location 块中，NGINX 按顺序执行其中的 rewrite 指令（如果存在）。匹配和替换过程与 server 上下文类似，但作用范围限于该 location 的 URI 模式。



根据标志决定后续行为：

- **无标志或 last**：重写 URI 后，NGINX 重新开始 location 匹配，基于新 URI 寻找最合适的 location 块。这可能导致进入新的 location 上下文并执行其中的 rewrite 指令。
- **break**：重写 URI 后，停止当前 location 上下文的 rewrite 指令处理，且不触发新的 location 匹配。NGINX 直接执行当前 location 块中的其他指令（如 proxy_pass 或 root）。
- **redirect 或 permanent**：返回 302 或 301 重定向，请求处理终止，客户端收到重定向响应。



**循环与终止**

**循环**：如果使用 last 标志，NGINX 会基于新 URI 重新搜索 location，可能触发新的 rewrite 指令。这种循环允许 URI 多次重写，但需小心避免无限循环（NGINX 内部限制循环次数，通常为 10 次）。

**终止**：以下情况会导致 rewrite 处理终止：

- 遇到 break 标志，停止当前上下文的 rewrite 处理。
- 返回重定向（redirect 或 permanent），请求处理结束。
- 当前 location 没有更多 rewrite 指令，NGINX 执行其他指令（如 proxy_pass、root 或 return）。
- 达到 NGINX 内部的重写循环限制，触发 500 错误。



示例 1：

```nginx
server {
    # ...
    rewrite ^(/download/.*)/media/(\w+)\.?.*$ $1/mp3/$2.mp3 last;
    rewrite ^(/download/.*)/audio/(\w+)\.?.*$ $1/mp3/$2.ra  last;
    return  403;
    # ...
   
    # localtion ... {
    # ...
}
```



URL：**/download/some/media/file** 重写为 **/download/some/mp3/file.mp3**，因 last 标志，后续指令（第二个 rewrite 和 return）被跳过，直接开始 location 匹配。

URL：**/download/some/audio/file** 重写为 **/download/some/mp3/file.ra**，因 last 标志，后续指令（return）被跳过，直接开始 location 匹配。



若 URI 不匹配任一 rewrite 指令，NGINX 会按照顺序执行 **rewrite** 后的 **return 403** 指令，返回 403 错误码。



示例 2：

```nginx
server {
    # ...
    rewrite ^/image/(.*)$ /img/$1 break;
	root /var/www/html/;
	# ...
}
```



### 重写 HTTP 响应

有时需要重写或替换 **HTTP 响应内容**，例如将一个字符串替换为另一个。使用 sub_filter 指令可定义替换规则，支持变量和连续替换。例如，将代理服务器的绝对链接从其他服务器改为当前服务器：

```nginx
location / {
    sub_filter      /blog/ /blog-staging/;
    sub_filter_once off;
}
```



另一个示例将 HTTP 协议从 `http://` 改为 `https://`，并将 **localhost** 地址替换为请求头中的主机名。**sub_filter_once** 指令控制是否对同一响应多次应用 **sub_filter**：

```nginx
location / {
    sub_filter     'href="http://127.0.0.1:8080/'    'href="https://$host/';
    sub_filter     'img src="http://127.0.0.1:8080/' 'img src="https://$host/';
    sub_filter_once on;
}
```

注意，已被 sub_filter 修改的响应部分不会再次被其他 sub_filter 替换。



### 处理错误

通过 **error_page** 指令，可配置 **NGINX** 返回自定义页面及错误码、替换错误码或将浏览器重定向到其他 URI。以下示例为 404 错误指定返回 **/404.html 页**面：

```nginx
error_page 404 /404.html;
```

注意，error_page 指令仅指定**错误处理方式**，**不会立即返回错误（return 指令用于此目的）**。错误码可能来自**代理服务器**或 **NGINX 处理过程中**（例如，找不到客户端请求的文件导致 404 错误）。



以下示例中，当 NGINX 找不到页面时，**将 404 错误替换为 301 重定向**，引导客户端访问 `http://example.com/new/path.html`。此配置适用于客户端仍尝试访问旧 URI 的场景，301 状态码通知浏览器页面已永久移动，需自动更新地址：

```nginx
location /old/path.html {
    error_page 404 =301 http://example.com/new/path.html;
}
```



以下配置展示当文件未找到时将请求传递给后端。由于 error_page 指令中的等号后未指定状态码，客户端收到的状态码由代理服务器返回（不一定是 404）：

```nginx
server {
    ...
    location /images/ {
        # 设置搜索文件的根目录
        root /data/www;

        # 禁用文件不存在相关的错误日志
        open_file_cache_errors off;

        # 文件未找到时执行内部重定向
        error_page 404 = /fetch$uri;
    }

    location /fetch/ {
        proxy_pass http://backend/;
    }
}
```

**error_page** 指令指示 NGINX 在文件未找到时执行内部重定向。**$uri** 变量保存当前请求的 **URI**，传递给重定向。例如，若 **/images/some/file** 未找到，则替换为 **/fetch/images/some/file**，并重新搜索 **location**，最终请求被代理到 `http://backend/`。





## 静态内容

### 根目录

**root 指令** 用于指定文件搜索的根目录。当 NGINX 处理请求时，它会将请求的 URI 追加到 `root` 指令所定义的路径之后，从而生成文件的完整访问路径。



该指令可以在 `http {}`、`server {}` 或 `location {}` 上下文中灵活配置。如果在较高层级（如 `server {}`）定义了 `root`，那么所有未单独指定 `root` 的 `location {}` 块都会继承该设置。

```nginx
server {
    root /www/data;

    location / {
    }

    location /images/ {
    }

    location ~ \.(mp3|mp4) {
        root /www/media;
    }
}
```

- 当请求的 **URI 以 `/images/` 开头** 时，NGINX 会默认在 `/www/data/images/` 目录下查找对应文件（继承 `server` 层级的 `root` 设置）。
- 如果请求的 **URI 以 `.mp3` 或 `.mp4` 结尾**，NGINX 则会优先在 `/www/media/` 目录中搜索，因为该 `location` 块内通过 `root` 指令覆盖了默认配置。



### alias

alias 会将请求的 URI（或其一部分）替换为指定的路径，而不直接追加到根目录路径后。**alias 指令只能在 location 块中使用。**

语法：

```nginx
alias path;
```



alias 指令直接用指定的路径替换 location 匹配的 URI 部分，剩余的 URI（如果有）会追加到 alias 路径后。**alias 指令会覆盖 root 指令。**

```nginx
server {
    root /www/data;
    
    location /image/ {  # 注意：此处为 image						location 1
    }

    location /images/ { # 注意：此处为 images		image(s)		location 2
        alias /img/;
    }
}
```

- 请求 URL `/image/photo.jpg`，匹配**第一个 location**，将请求的 URI ``/image/photo.jpg` 追加到 `root` 指令所定义的 `/www/data` 路径之后，文件完整访问路径为 `/www/data/iamge/photo.jpg`。
- 请求 URL `/images/photo.jpg`，匹配**第二个 location**，将 location 匹配的 URL 部分（`/images/`）替换为 alias 指定的路径（`/img`），文件完整访问路径为 `/img/photo.jpg`。**alias 指令会覆盖 root 指令。**





### 索引文件

当请求的 URI 以斜杠（/）结尾时，NGINX 会将其视为目录请求，并尝试在该目录下查找索引文件。**索引文件的名称由 `index` 指令定义**，默认值为 `index.html`。

例如，当请求的 URI 为 `/images/some/path/` 时，NGINX 会尝试返回 `/www/data/images/some/path/index.html`。如果该文件不存在，NGINX 默认返回 **HTTP 404（未找到）** 状态码。



**`index` 指令支持多个文件名**，NGINX 会按顺序查找并返回第一个匹配的文件。例如：

```nginx
location / {
    index index.$geo.html index.htm index.html;
}
```

此处使用的 **$geo** 是一个通过 **geo** 指令设置的自定义变量，其值取决于客户端的 IP 地址。



在 NGINX 处理索引文件时，**会先检查文件是否存在**，然后对追加了索引文件名的 URI 执行内部重定向。**内部重定向会触发新的 location 匹配**，可能导致请求进入不同的 location 块。以下是一个典型示例：

```nginx
location / {
    root /data;
    index index.html index.php;
}

location ~ \.php {
    fastcgi_pass localhost:8000;
    # ...
}
```

以请求 URI `/` 为例，请求首先匹配 `location /` 块，因为 URI 不符合 `\.php$` 或 `\.phps$` 的正则表达式规则。

- **root /data** 指令将文件搜索根目录设置为 `/data`。
- **index 指令** 使 NGINX 按顺序检查索引文件：`index.html` 和 `index.php`



**检查 /data/index.html**

NGINX 首先尝试访问 `/data/index.html`。

**若文件存在**：执行内部重定向（URI 修改为 `/index.html`），`/index.html` 仍然被 `location /` 匹配，返回该静态文件内容。

**假设场景**：文件不存在，继续检查下一个索引文件。



**检查 /data/index.php**

NGINX 接着检查 `/data/index.php`。

**若文件存在**：执行内部重定向，将 URI 修改为 `/index.php`。

**重定向影响**：新的 URI `/index.php` 会匹配 `location ~ \.php` 块，触发 FastCGI 代理将请求转发至 `localhost:8000` 后端服务。



若希望 NGINX 返回自动生成的目录列表，可在  `autoindex` 指令中设置参数为 `on` ：

```nginx
location /images/ {
    autoindex on;
}
```



### try_files

`try_files` 指令用于检查指定的文件或目录是否存在。若存在，则直接提供服务或执行内部重定向；若均不存在，则返回指定的状态码或重定向到其他位置。

上下文：可在 `server {}` 或 `location {}` 块中使用。



语法

```
try_files file ... uri | =code;
```

- **`file ...`**：按顺序检查的文件或目录路径，支持绝对路径、相对路径或变量（如 `$uri`）。
- **`uri`**：若所有文件或目录均不存在，则执行内部重定向到该 URI。
- **`=code`**：若所有文件或目录均不存在，则返回指定的 HTTP 状态码（如 `=404`）。



**示例 1：检查文件是否存在**

```nginx
server {
    root /www/data;

    location /images/ {
        try_files $uri /images/default.gif;
    }
}
```

- 检查请求 URI（如 `/images/photo.jpg`）对应的文件 `/www/data/images/photo.jpg` 是否存在。
- 若存在，返回该文件；若不存在，返回默认文件 `/www/data/images/default.gif`。



**示例 2：检查文件、目录或返回 404**

```nginx
location / {
    root /www/data;
    try_files $uri $uri/ $uri.html =404;
}
```

- 检查请求 URI（如 `/path`）对应的文件 `/www/data/path` 是否存在。
- 若不存在，检查目录 `/www/data/path/` 是否存在（需配合 `index` 指令查找索引文件）。
- 若仍不存在，检查文件 `/www/data/path.html` 是否存在。
- 若均不存在，返回 HTTP 404 状态码。



**示例 3：转发到后端**

```nginx
location / {
    root /www/data;
    try_files $uri $uri/ @backend;
}

location @backend {
    proxy_pass http://backend.example.com;
}
```

- 检查 `$uri` 和 `$uri/` 是否存在。
- 若均不存在，重定向到命名 `location @backend`，并将请求代理至后端服务器 `http://backend.example.com`。



### 性能优化

优化内容服务性能的关键在于提升加载速度。通过对 NGINX 配置进行精细调整，可以显著提高效率，从而实现最佳性能。



#### 启用 sendfile

默认情况下，NGINX 在文件传输时会将文件内容先复制到缓冲区再发送。启用 `sendfile` 指令可以省去这一缓冲区复制步骤，实现数据从一个文件描述符到另一个的直接复制。为了避免单一快速连接完全占用工作进程，可以使用 `sendfile_max_chunk` 指令限制单次 `sendfile()` 调用传输的数据量，例如限制为 1MB：

```nginx
location /mp3 {
    sendfile           on;
    sendfile_max_chunk 1m;
    # ...
}
```



#### 启用 tcp_nopush

当 `sendfile` 处于开启状态时，结合使用 `tcp_nopush` 指令，可以让 NGINX 在通过 `sendfile()` 获取数据块后，立即将 HTTP 响应头与数据打包发送：

```nginx
location /mp3 {
    sendfile   on;
    tcp_nopush on;
    # ...
}
```



#### 启用 tcp_nodelay

`tcp_nodelay` 指令用于禁用 Nagle 算法。Nagle 算法最初是为了解决慢速网络中小数据包传输问题而设计的，它会将多个小数据包合并为一个较大包，并延迟 200 毫秒发送。然而，在服务大型静态文件时，数据可以立即发送，无需考虑包大小。此外，这种延迟也会影响在线应用，例如 SSH、在线游戏和在线交易等。默认情况下，`tcp_nodelay` 被设置为 `on`，即禁用 Nagle 算法。建议仅对保持连接（keepalive）使用此指令：

```nginx
location /mp3 {
    tcp_nodelay       on;
    keepalive_timeout 65;
    # ...
}
```



#### 优化 backlog 队列

NGINX 处理传入连接的速度是一个关键因素。通常，连接建立后会被放入监听套接字的“监听”队列。在正常负载下，这个队列通常较小或不存在。然而，在高负载情况下，队列可能急剧增长，这会导致性能不均、连接断开或延迟增加。



#### 显示监听队列

运行 `netstat -Lan` 命令可以查看当前的监听队列。输出结果可能如下所示，其中显示端口 80 的监听队列中有 10 个未接受的连接，最大配置为 128 个，这属于正常情况：

```
Current listen queue sizes (qlen/incqlen/maxqlen)
Listen         Local Address
0/0/128        *.12345
10/0/128       *.80
0/0/128        *.8080
```

相反，如果未接受连接数（例如 192）超过了限制（128），则表明网站正在经历高流量。为了优化性能，需要在操作系统和 NGINX 配置中增加可排队的最大连接数：

```
Current listen queue sizes (qlen/incqlen/maxqlen)
Listen         Local Address
0/0/128        *.12345
192/0/128      *.80
0/0/128        *.8080	
```



#### 调整操作系统

将 `net.core.somaxconn` 内核参数从默认值（128）增加到足以应对大流量突发的值，例如 4096。

对于 FreeBSD 系统，可以运行：

```
sudo sysctl kern.ipc.somaxconn=4096
```

对于 Linux 系统，可以运行：

```
sudo sysctl -w net.core.somaxconn=4096
```

同时，将以下内容添加到 `/etc/sysctl.conf` 文件中：

```
net.core.somaxconn = 4096
```



#### 调整 NGINX

如果 `somaxconn` 参数被设置为大于 512 的值，则需要调整 NGINX `listen` 指令的 `backlog` 参数以匹配：

```nginx
server {
    listen 80 backlog=4096;
    # ...
}
```



## 反向代理

**反向代理**是一种重要的服务器架构技术，主要用于实现**在多个服务器之间均衡负载**、**无缝整合不同网站的内容**，以及**将请求转发至支持非 HTTP 协议的应用服务器**（例如基于 PHP 或 Python 等特定框架开发的应用）。

当 NGINX 作为反向代理处理请求时，其工作流程分为三个关键步骤：

1. **将客户端请求转发至指定的代理服务器**；
2. 2**接收并处理来自代理服务器的响应**；
3. **将处理后的响应返回给客户端**。



**NGINX 的代理功能**支持将请求转发至多种类型的服务器，包括 **HTTP 服务器**（如其他 NGINX 实例或任意 Web 服务器）和 **非 HTTP 服务器**（如运行 FastCGI、uwsgi、SCGI 或 memcached 协议的应用服务器）。这使得 NGINX 能够灵活适配不同的后端服务架构。

要通过 NGINX 将请求代理到 HTTP 服务器，只需在 `location` 块中使用 `proxy_pass` 指令。例如：

```nginx
location /some/path/ {
    proxy_pass http://www.example.com/link/;
}
```

如果 `proxy_pass` 指令的**目标地址中指定了 URI 路径**（如 `/link/`），NGINX 会将该路径替换掉**客户端请求 URI 中与 `location` 匹配的部分。**在这里示例中将会使用 `/link/` 替换 `/some/path/`

- **客户端请求**：`/some/path/page.html`
- **代理后的目标地址**：`http://www.example.com/link/page.html`
- **客户端请求**：`/some/path/sub_path/page.html`
- **代理后的目标地址**：`http://www.example.com/link/sub_path/page.html`



此配置会将所有匹配该路径的请求转发至指定的代理服务器地址。目标地址可以是 **域名** 或 **IP 地址**，并支持指定端口号：

```nginx
location ~ \.php {
    proxy_pass http://127.0.0.1:8000;
}
```

如果地址未指定URI，或者无法确定要替换的URI部分，则会传递完整的请求URI（可能会稍作修改）。



要将请求代理到 **非 HTTP 服务器**（如 FastCGI、uWSGI 等），需使用对应的 `*_pass` 指令：

- **`fastcgi_pass`**：转发至 FastCGI 服务器（如 PHP-FPM）
- **`uwsgi_pass`**：转发至 uWSGI 服务器（常用于 Python 应用）
- **`scgi_pass`**：转发至 SCGI 服务器
- **`memcached_pass`**：转发至 memcached 服务器

非 HTTP 代理的地址规则可能与 HTTP 代理不同，需参考具体协议文档。通常需要额外传递参数（如 `fastcgi_param`），确保后端服务器正确处理请求。

`proxy_pass` 还支持将请求转发至 **预定义的服务器组**（如 `upstream` 块定义的集群），此时请求会按配置的负载均衡策略（轮询、最少连接等）在组内分发。



### 传递请求头

默认情况下，NGINX 会修改代理请求中的两个头部字段：**"Host"** 和 **"Connection"**，并删除值为空字符串的头部字段。其中，**"Host"** 被设置为 **$proxy_host** 变量的值，**"Connection"** 被设置为 **close**。

要更改这些设置或修改其他头部字段，可使用 **proxy_set_header** 指令。该指令可在 location 块、特定 server 上下文或 http 块中指定。例如：

```nginx
location /some/path/ {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_pass http://localhost:8000;
}
```

在此配置中，**"Host"** 字段被设置为 **$host** 变量的值。



要阻止某个头部字段传递到被代理服务器，可将其**设置为空字符串**，如下所示：

```nginx
location /some/path/ {
    proxy_set_header Accept-Encoding "";
    proxy_pass http://localhost:8000;
}
```



### 配置缓冲

默认情况下，NGINX 会缓冲来自被代理服务器的响应，将其存储在内部缓冲区中，直到整个响应接收完毕才发送给客户端。这种缓冲机制有助于优化与慢速客户端的性能；如果响应直接同步传递给客户端，可能会浪费被代理服务器的处理时间。启用缓冲时，NGINX 允许被代理服务器快速处理响应，同时根据客户端的下载速度存储这些数据。

负责启用或禁用缓冲的关键指令是 **proxy_buffering**，其默认设置为 **on**，表示启用状态。

**proxy_buffers** 和 **proxy_buffer_size** 指令共同控制 NGINX 存储和缓冲数据的方式。



**proxy_buffers** 定义了为请求分配的缓冲区数量和大小；

响应的第一部分（通常包含较小的响应头部）则存储在由 **proxy_buffer_size** 设置的单独缓冲区中，该部分可以配置为比其他缓冲区更小。

以下示例增加了默认缓冲区数量，并将响应的第一部分的缓冲区大小设置为比默认值更小：

```nginx
location /some/path/ {
    proxy_buffers 16 4k;
    proxy_buffer_size 2k;
    proxy_pass http://localhost:8000;
}
```



如果禁用缓冲，响应会在从被代理服务器接收时同步发送给客户端，这种行为适合需要尽快接收响应的快速交互客户端。要在特定 location 中禁用缓冲，可将 **proxy_buffering** 指令设置为 **off**。

```nginx
location /some/path/ {
    proxy_buffering off;
    proxy_pass http://localhost:8000;
}
```

在此情况下，NGINX 仅使用 **proxy_buffer_size** 配置的缓冲区存储响应当前部分。

反向代理常用于负载均衡场景；若需深入了解如何通过快速部署提升应用性能、能力和专注度，可参阅免费电子书《选择软件负载均衡器的五大理由》。



### 选择出站IP地址

如果您的代理服务器具有多个网络接口，有时可能需要**选择特定的源IP地址**来连接到被代理服务器或上游服务器。当 NGINX 后面的被代理服务器配置为只接受来自特定 IP 网络或 IP 地址范围的连接时，这尤其有用。

在这种情况下，可以使用 **proxy_bind** 指令指定所需的网络接口 IP 地址。以下是一个配置示例：

```nginx
location /app1/ {
    proxy_bind 127.0.0.1;
    proxy_pass http://example.com/app1/;
}

location /app2/ {
    proxy_bind 127.0.0.2;
    proxy_pass http://example.com/app2/;
}
```



此外，IP 地址也可以通过变量来指定。例如，**$server_addr** 变量用于传递接受请求的网络接口的 IP 地址：

```nginx
location /app3/ {
    proxy_bind $server_addr;
    proxy_pass http://example.com/app3/;
}
```



## SSL

要在 NGINX 上配置 HTTPS 服务器，需要在 nginx.conf 文件的 server 块中为 **listen** 指令添加 **ssl** 参数，并指定服务器证书和私钥文件的路径。例如：

```nginx
server {
    listen              443 ssl;
    server_name         www.example.com;
    ssl_certificate     www.example.com.crt;
    ssl_certificate_key www.example.com.key;
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    #...
}
```



**服务器证书**是公开的，会发送给每个连接到 NGINX 服务器的客户端。**私钥是敏感信息**，必须存储在访问受限的文件中，同时确保 NGINX 主进程能够读取它。或者，私钥可以与证书存储在同一个文件中：

```nginx
ssl_certificate     www.example.com.cert;
ssl_certificate_key www.example.com.cert;
```

在这种情况下，必须严格限制对文件的访问权限。请注意，即使证书和私钥存储在同一文件中，发送给客户端的只有证书。



通过 **ssl_protocols** 和 **ssl_ciphers** 指令，可以强制客户端仅使用安全的 SSL/TLS 版本和加密算法建立连接。

自 NGINX 1.9.1 版本起，默认配置如下：

```nginx
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers HIGH:!aNULL:!MD5;
```

由于旧版加密算法可能存在设计漏洞，**建议在现代 NGINX 配置中禁用这些算法**（NGINX 默认配置因向后兼容性而不易更改）。

**CBC 模式加密算法易受攻击**（如 CVE-2011-3389 中的 BEAST 攻击），并且 **SSLv3 不建议使用**，因为它容易受到 POODLE 攻击，除非必须支持旧版客户端。



### OCSP 验证

NGINX 能够通过在线证书状态协议（OCSP）验证 X.509 客户端证书的有效性。NGINX 会向 OCSP 响应者发送请求，以检查证书状态，并返回以下三种结果之一：

- **有效**：证书未被吊销。
- **已吊销**：证书已被吊销。
- **未知**：无客户端证书的相关信息。



要启用客户端证书的 OCSP 验证，需要结合使用 **ssl_verify_client** 指令和 **ssl_ocsp** 指令。以下配置示例展示了如何实现这一功能：

```nginx
server {
    listen 443 ssl;

    ssl_certificate     /etc/ssl/foo.example.com.crt;
    ssl_certificate_key /etc/ssl/foo.example.com.key;

    ssl_verify_client       on;
    ssl_trusted_certificate /etc/ssl/cachain.pem;
    ssl_ocsp                on; # 启用 OCSP 验证

    #...
}
```



默认情况下，NGINX 会使用客户端证书中嵌入的 OCSP URI 发送请求。如果需要指定其他 OCSP 响应者 URI，可以通过 **ssl_ocsp_responder** 指令来定义。注意，仅支持 http:// 协议的响应者：

```nginx
#...
ssl_ocsp_responder http://ocsp.example.com/;
#...
```



为了在所有工作进程之间共享缓存的 OCSP 响应，可以使用 **ssl_ocsp_cache** 指令来定义缓存的名称和大小。默认情况下，响应缓存的有效期为 1 小时，除非 OCSP 响应的 nextUpdate 字段指定了其他时间：

```nginx
#...
ssl_ocsp_cache shared:one:10m;
#...
```



### 优化

SSL 操作会消耗额外的 CPU 资源，其中 **SSL 握手是最消耗资源的操作**。减少每个客户端的 SSL 握手次数的有效方法包括：

1. **启用 keepalive 连接**：通过单一连接发送多个请求。
2. **重用 SSL 会话参数**：避免并行或后续连接的 SSL 握手。



会话参数存储在所有工作进程共享的 SSL 会话缓存中，可通过 **ssl_session_cache** 指令配置。1 MB 缓存可存储约 4000 个会话。默认缓存超时为 5 分钟，可通过 **ssl_session_timeout** 指令调整。以下配置示例针对多核系统优化，设定了 10 MB 共享会话缓存和 10 分钟超时：

```nginx
worker_processes auto;

http {
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    server {
        listen              443 ssl;
        server_name         www.example.com;
        keepalive_timeout   70;

        ssl_certificate     www.example.com.crt;
        ssl_certificate_key www.example.com.key;
        ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        #...
    }
}
```



#### 证书链

某些浏览器可能**对证书颁发机构签发的证书提出警告**，而其他浏览器则正常接受。这是因为颁发机构使用了中间证书进行签名，但该中间证书**未包含在某些浏览器的可信证书库中**，导致证书链验证失败。

为解决此问题，颁发机构通常会提供一个证书链束文件。需将其与服务器证书拼接在一起，并确保**服务器证书位于拼接文件的首位**。例如，使用命令行工具拼接：

```bash
cat www.example.com.crt bundle.crt > www.example.com.chained.crt
```



拼接后的文件应在 NGINX 的 `ssl_certificate` 指令中引用，配置示例如下：

```nginx
server {
    listen              443 ssl;
    server_name         www.example.com;
    ssl_certificate     www.example.com.chained.crt;
    ssl_certificate_key www.example.com.key;
    #...
}
```



如果证书和链束拼接顺序错误（例如，链束在前），NGINX 将无法启动，并显示类似错误：

```nginx
SSL_CTX_use_PrivateKey_file(" ... /www.example.com.key") failed
   (SSL: error:0B080074:x509 certificate routines:
    X509_check_private_key:key values mismatch)
```

此错误表明 NGINX 尝试将私钥与链束中的第一个证书（而非服务器证书）配对，导致密钥不匹配。



值得注意的是，常用浏览器（如 Chrome 或 Firefox）通常已存储由可信机构签名的中间证书，因此可能不会因缺少链束而报错。但为确保服务器发送完整的证书链，建议使用 openssl 命令行工具验证：

```bash
openssl s_client -connect www.godaddy.com:443
...
Certificate chain
 0 s:/C=US/ST=Arizona/L=Scottsdale/1.3.6.1.4.1.311.60.2.1.3=US
     /1.3.6.1.4.1.311.60.2.1.2=AZ/O=GoDaddy.com, Inc
     /OU=MIS Department/CN=www.GoDaddy.com
     /serialNumber=0796928-7/2.5.4.15=V1.0, Clause 5.(b)
   i:/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc.
     /OU=http://certificates.godaddy.com/repository
     /CN=Go Daddy Secure Certification Authority
     /serialNumber=07969287
 1 s:/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc.
     /OU=http://certificates.godaddy.com/repository
     /CN=Go Daddy Secure Certification Authority
     /serialNumber=07969287
   i:/C=US/O=The Go Daddy Group, Inc.
     /OU=Go Daddy Class 2 Certification Authority
 2 s:/C=US/O=The Go Daddy Group, Inc.
     /OU=Go Daddy Class 2 Certification Authority
   i:/L=ValiCert Validation Network/O=ValiCert, Inc.
     /OU=ValiCert Class 2 Policy Validation Authority
     /CN=http://www.valicert.com//emailAddress=info@valicert.com
...
```

在此示例中，服务器证书（#0）的颁发者是证书 #1 的主体，证书 #1 的颁发者是证书 #2 的主体，而证书 #2 由知名机构 ValiCert, Inc. 签名，其证书已内置于浏览器中。如果未添加证书链束，仅发送服务器证书（#0），可能导致验证问题。



在 HTTPS 通信中，服务器发送的证书链通常**只包含终端证书和中间证书**，而**不包含根 CA 证书**。这主要是因为根 CA 证书的信任机制和分发方式与中间证书及终端证书有所不同。

几乎所有的根 CA 证书都已**预装在操作系统和浏览器中**，存储于客户端的信任区。这种信任机制是在硬件制造或软件开发时，通过严格的实体手段建立的，它与中间证书和终端证书那种基于上级证书签名验证的信任方式是不同的。

由于根 CA 证书已预装在客户端的信任存储中，服务器**无需在证书链中包含它**。客户端会从本地信任存储中查找相应的根证书，以完成信任链的验证。

如果根 CA 证书未预装在客户端，即便服务器在证书链中包含了根证书，客户端的操作系统或浏览器也**不会信任它**，因为其信任模型依赖于预装的根证书，而非服务器提供的证书。



### SNI

**服务器名称指示（SNI）** 是一种在 **SSL/TLS 握手** 期间，允许浏览器传递其请求的服务器名称的机制。这使得服务器能够识别客户端要访问的具体域名，并据此提供正确的 SSL 证书。



在早期的 SSL 协议中，当多个 HTTPS 服务器被配置为监听同一 IP 地址时，通常会遇到一个问题。例如，在以下 NGINX 配置中：

```nginx
server {
    listen          443 ssl;
    server_name     www.example.com;
    ssl_certificate www.example.com.crt;
    #...
}

server {
    listen          443 ssl;
    server_name     www.example.org;
    ssl_certificate www.example.org.crt;
    #...
}
```

在这种配置下，无论浏览器实际请求的是 `www.example.com` 还是 `www.example.org`，它都将收到默认服务器块（`server block`）的证书，例如 `www.example.com` 的证书。这主要是由于 **SSL 协议的固有行为** 导致的：SSL 连接是在浏览器发送 HTTP 请求之前建立的。因此，NGINX 在 SSL 握手阶段无法得知客户端请求的具体服务器名称，只能提供其配置的默认服务器证书。

然而，在 **现代 TLS 协议** 中，SNI 的引入解决了这一难题。它允许浏览器在 SSL 握手过程中，提前告知服务器其希望连接的服务器名称，从而使服务器能够 **根据该名称选择并提供正确的 SSL 证书**。



#### 包含多个名称的 SSL 证书

在单个 IP 地址上运行多个 HTTPS 服务器，除了使用 **SNI（Server Name Indication）** 外，还有其他几种方法。其中一种是使用 **包含多个名称的 SSL 证书**。这类证书通常在 **SubjectAltName (SAN) 字段** 中包含多个域名，例如 `www.example.com` 和 `www.example.org`。然而，需要注意的是，SAN 字段的长度是有限的。

另一种常见方法是使用 **通配符证书**，例如 `*.example.org`。通配符证书能够保护指定域名的所有 **一级子域名**（如 `a.example.org`, `b.example.org`），但 **不适用于根域名**（如 `example.org`）或 **多级子域名**（如 `www.sub.example.org`）。

这两种方法也可以结合使用。例如，证书的 SubjectAltName 字段可以同时包含 **精确名称和通配符名称**，如 `example.org` 和 `*.example.org`。

为了优化性能并有效利用内存，建议将包含多个名称的证书及其私钥文件配置在 **http 级别**。这样做可以确保在所有服务器之间共享单一的内存副本，避免重复加载，从而提升效率。

以下是相应的 NGINX 配置示例：

```nginx
ssl_certificate     common.crt;
ssl_certificate_key common.key;

server {
    listen          443 ssl;
    server_name     www.example.com;
    #...
}

server {
    listen          443 ssl;
    server_name     www.example.org;
    #...
}
```



