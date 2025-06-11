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



