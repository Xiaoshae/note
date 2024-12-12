# header

header — 发送原生 HTTP 头

```php
header(string $string, bool $replace = true, int $response_code = ?): void
```

header() 用于发送原生的 HTTP 头。

关于 HTTP 头的更多信息请参考：[ RFC 2616 |» HTTP/1.1 specification](https://datatracker.ietf.org/doc/html/rfc2616)



请注意 **header()** 必须**在任何实际输出之前调用**，不管是普通的 **HTML 标签**，还是**文件**或 **PHP 输出的空行，空格**。

这是个常见的错误，在通过**include**，**require**，或者其访问其他文件里面的函数的时候，如果在header()被调用之前，其中有空格或者空行。 同样的问题也存在于单独的 PHP/HTML 文件中。

```php+HTML
<html>
<?php
/* 这将导致错误。请注意上面的输出
 * 它在 header() 调用之前 */
header('Location: http://www.example.com/');
exit;
?>
```



## 参数

**string**

头字符串。有两种特别的头。

第一种以“`HTTP/`”开头的 (case is not significant)，将会被用来计算出将要发送的HTTP状态码。 例如在 Apache 服务器上用 PHP 脚本来处理不存在文件的请求（使用 `ErrorDocument` 指令）， 就会希望脚本响应了正确的状态码。

```php+HTML
<?php
// 本示例演示了 "HTTP/" 的特殊例子，典型用法的最佳实践，包括：
// 1. header($_SERVER["SERVER_PROTOCOL"] . " 404 Not Found");
//    （覆盖 http 状态消息，兼容还在使用 HTTP/1.0 的客户端）
// 2. http_response_code(404); （使用默认消息）
header("HTTP/1.1 404 Not Found");
?>
```

第二种特殊情况是“Location:”的头信息。它不仅把报文发送给浏览器，而且还将返回给浏览器一个 `REDIRECT`（302）的状态码，除非状态码已经事先被设置为了`201`或者`3xx`。

```php+HTML
<?php
header("Location: http://www.example.com/"); /* 重定向浏览器 */

/* 确保重定向时不会执行下面的代码. */
exit;
?>
```



**replace**

可选参数 **replace** 表明是否用后面的头替换前面相同类型的头。 默认情况下会替换。如果传入 **false**，就可以强制使相同的头信息并存。例如：

```php+HTML
<?php
header('WWW-Authenticate: Negotiate');
header('WWW-Authenticate: NTLM', false);
?>
```



**response_code**

强制指定 HTTP 响应的值。注意，这个参数只有在报文字符串（**header**）不为空的情况下才有效。



**示例 #1 下载对话框**

如果你想提醒用户去保存你发送的数据，例如保存一个生成的PDF文件。你可以使用[ RFC 2183 |» Content-Disposition](https://datatracker.ietf.org/doc/html/rfc2183)的报文信息来提供一个推荐的文件名，并且强制浏览器显示一个文件下载的对话框。

```php
<?php
// 输出 PDF 文件
header('Content-type: application/pdf');

// 名称为 downloaded.pdf
header('Content-Disposition: attachment; filename="downloaded.pdf"');

// 该 PDF 来源于 original.pdf
readfile('original.pdf');
?>
```



**示例 #2 缓存指令**

PHP 脚本经常生成一些动态内容，它不该被客户端、服务器与浏览器之间的代理缓存。 许多代理与客户端都支持这样强制禁用缓存：

```php
<?php
header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT"); // 过去的日期
?>
```

> 注意：也许你会遇到这样的情况，那就是即使你没使用上面这段代码，你的页面也没有被缓存。大多数情况是因为用户可以自己设置他们的浏览器从而改变浏览器默认的缓存行为。一旦发送了上面这段报文信息，那么你就应该重写那些可能用到缓存了的代码。
>
> 此外，在启用session的情况下，**session_cache_limiter()** 和 **session.cache_limiter** 的配置可以用来自动地生成正确的缓存相关的头信息。



**示例 #3 设置一个 Cookie**

**setcookie()** 提供了一个方便的方式来设置 Cookie。 要设置一个包含 **setcookie()** 函数不支持的属性的 **Cookie**，可以使用 **header()**。

例如，以下代码设置了一个包含 `Partitioned` 属性的 Cookie。

```php
<?php
header('Set-Cookie: name=value; Secure; Path=/; SameSite=None; Partitioned;');
?>
```



## 返回值

没有返回值。



## 错误／异常

当 header 发送失败时，**header() 会抛出 E_WARNING** 级别的错误



# headers_sent

headers_sent — 检测消息头是否已经发送

```php
headers_sent(string &$filename = null, int &$line = null): bool
```

检测消息头是否已经发送。

消息头已经发送时，就无法通过 **header()** 添加更多头字段。使用此函数起码可以防止收到跟消息头相关的错误。另一个解决方案是用输出缓冲。



## 参数

**filename**

若设置了可选参数 **filename 和 line**，**headers_sent()** 会把 PHP 文件名放在 **filename** 变量里，输出开始的行号放在 **line** 变量里。

> 注意：如果在**执行 PHP 源文件之前已经开始输出**（例如由于启动错误），则 **filename 参数将被设置为空字符串**。
>



**line**

输出开始的行号。



## 返回值

消息头未发送时，**headers_sent()** 返回 **false**，否则返回 **true**。



**示例 #1 使用 \**headers_sent()\** 的例子**

```php
<?php

// 没有消息头就发送一个
if (!headers_sent()) {
    header('Location: http://www.example.com/');
    exit;
}

// 使用 file 和 line 参数选项的例子
// 注意 $filename 和 $linenum 用于下文中使用
// 所以不要提前为它们赋值
if (!headers_sent($filename, $linenum)) {
    header('Location: http://www.example.com/');
    exit;

// 很有可能在这里触发错误
} else {

    echo "Headers already sent in $filename on line $linenum\n" .
          "Cannot redirect, for now please click this <a " .
          "href=\"http://www.example.com\">link</a> instead\n";
    exit;
}

?>
```

