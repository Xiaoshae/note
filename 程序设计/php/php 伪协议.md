# php 伪协议



## data://

data:// ，它是 RFC 2397 中定义的一种用于在URL中内联数据的方案

数据 URI 的格式如下：

```
data:[<mediatype>][;base64],<data>
```

注：在 php 中允许使用  data: 或 data:// ， 但是 RFC 2397 中的标准格式时 data:



示例：

```
data:text/plain;charset=US-ASCII;base64,helloworld
```

MIME 类型（如 `text/plain` 、 `charset=US-ASCII` 、`base64`）可以包含多个部分，这些部分通过分号 `;` 分割

**`<data>`数据部分**与 MIME 类型和参数之间用逗号 `,` 分隔



### MIME

MIME 于指示电子邮件或HTTP消息中的文件类型，它不仅限于文本数据，还支持多种媒体类型的数据传输。

它不仅限于文本数据，还支持多种媒体类型的数据传输。

**文本类型**

- `text/html`：HTML格式的文本。
- `text/css`：CSS样式表。
- `text/javascript`：JavaScript代码。
- `text/xml`：XML格式的文本。

**图像类型**

- `image/jpeg`：JPEG图像。
- `image/png`：PNG图像。
- `image/gif`：GIF图像。
- `image/svg+xml`：SVG图像。

**视频类型**

- `video/mp4`：MP4视频格式。
- `video/quicktime`：QuickTime视频格式。
- `video/mpeg`：MPEG视频格式。

**音频类型**

- `audio/mpeg`：MP3音频格式。
- `audio/wav`：WAV音频格式。
- `audio/aac`：AAC音频格式。

**应用程序类型**

- `application/pdf`：PDF文档。
- `application/json`：JSON格式的数据。
- `application/xml`：XML格式的数据。
- `application/octet-stream`：二进制数据流，通常用于下载文件。
- `application/x-www-form-urlencoded`：URL编码的表单数据。
- `application/x-tar`：tar压缩文件。
- `application/zip`：ZIP压缩文件。

**多部分类型**

- `multipart/form-data`：用于文件上传等场景，包含多个部分的数据。
- `multipart/mixed`：用于组合不同类型的资源。
- `multipart/alternative`：用于提供同一信息的不同版本（如纯文本和平面HTML）。

**其他类型**

- `message/rfc822`：电子邮件消息。
- `model/iges`：IGES模型数据。
- `font/ttf`：TrueType字体文件。
- `font/otf`：OpenType字体文件。



除了 `base64` 编码外，`data:` URI方案没有提供其他类似的编码方式。如果不使用 `;base64`，则数据应以未编码的形式提供，即以纯文本形式出现。



### data size

`data:` URI 方案确实存在一些大小上的限制，这些限制主要取决于浏览器或其他客户端如何处理这些URI。

虽然HTTP规范本身并没有对`data:` URI的大小设定具体的上限，但是各个浏览器和客户端可能会有自己的实现限制。



**浏览器中的限制**

**Chrome**： 对 data: URI 的支持没有明确的最大长度限制，但在实际使用中，非常大的 data: URI 可能会导致性能问题或内存溢出错误。

**Edge**： Microsoft Edge 没有明确的大小限制，但处理大文件时的表现与 Chrome 类似。

**Firefox**： Firefox 对 data: URI 的最大长度没有明确的限制，但同样，非常大的 data: URI 可能会影响页面加载速度和浏览器性能。

**Safari：** Safari 对 data: URI 的长度有限制，早期版本中这个限制大约是 1MB，但新版本中这个限制已经被提高。

**Internet Explorer**： IE9 和更早版本对 data: URI 的大小限制为 32KB。IE10 和 IE11 提高了这个限制，但具体数值不详。



**PHP中的限制**

在PHP中，当你生成一个包含 `data:` URI 的响应时，你需要注意服务器配置中的一些设置，比如 `memory_limit` 和 `post_max_size`，这些设置可能间接影响你能发送多大的 `data:` URI 数据。

**memory_limit**：设置了一个 **PHP 脚本在整个执行过程**中可以使用的**最大内存量**（**128MB**）。

**post_max_size**：通过 **POST 方法**提交给 PHP 脚本**的数据的最大大小**（**8M**）



### Note

当传递未经过 Base64 编码的普通字符串时，不要忘记通过 urlencode() 函数对字符串进行编码。

当你在 PHP 中使用 `fopen` 或其他函数处理 Data URI Scheme 时，PHP 会自动对传递的字符串进行 URL 解码。

如果你直接传递未经 URL 编码的字符串，其中的特殊字符（如 `+` 和 `%`）会被错误地解释和转换。



在这种情况下，PHP 严格遵守 RFC 2397。该标准第 3 节指出，传递的数据应采用 Base64 编码或 URL 编码。



**正确的使用方法：**

```php
<?php

$fp = fopen('data:text/plain,' . urlencode($data), 'rb'); // URL 编码的数据

$fp = fopen('data:text/plain;base64,' . base64_encode($data), 'rb'); // Base64 编码的数据

?>
```



**错误用法演示：**

```php
<?php

$data = 'Günther says: 1+1 is 2, 10%40 is 20.';

$fp = fopen('data:text/plain,' . $data, 'rb'); // 错误，千万不要这样做

echo stream_get_contents($fp);

// Günther says: 1 1 is 2, 10@ is 20. // 错误结果

fclose($fp);
?>
```



## php://

### stdin stdout stderr

`php://stdin`、`php://stdout` 和 `php://stderr` 允许直接访问 PHP 进程相应的输入或者输出流。

标准输入流通常是指从**命令行接口接收用户输入**的地方。

数据流引用了复制的文件描述符，所以如果你打开 php://stdin 并在之后关了它， 仅是关闭了复制品，真正被引用的 **`STDIN`** 并不受影响。

```php
$f = fopen("php://stdin","r");
fread($f,100);
fclose($f);
```



 推荐你简单使用常量 **`STDIN`**、 **`STDOUT`** 和 **`STDERR`** 来代替手工打开这些封装器。

```php
fread(STDIN,100);
```



php://stdin 是只读的， php://stdout 和 php://stderr 是只写的。



### input

`php://input` 是个可以访问请求的**原始数据**（**POST发送的数据**）的只读流。

如果启用了 **enable_post_data_reading** 选项（默认开启）， `php://input` 在使用 **enctype="multipart/form-data"** 的 POST 请求中不可用。

如果 **HTTP** 请求中 **header** 包含 `Content-Type: multipart/form-data; xxxx` 则无法使用 `php://input`

```php
<?php

echo file_get_contents("php://input");

?>
```

![image-20241017215753626](./images/php%20%E4%BC%AA%E5%8D%8F%E8%AE%AE.assets/image-20241017215753626.png)



### output

php://output 是一个只写的数据流，允许你以 print 和 echo 一样的方式 写入到输出缓冲区。

```php
<?php

file_put_contents("php://output","hello");  // 等价于  echo "hello"

?>
```



### fd

php://fd 允许直接访问指定的文件描述符。 例如 php://fd/3 引用了文件描述符 3。



### memory temp

php://memory 和 php://temp 是一个类似文件 包装器的数据流，允许读写临时数据。 

两者的一个区别是 php://memory 总是把数据储存在内存中， 而 php://temp 会在内存量达到预定义的限制后（默认是 2MB）存入临时文件中。

临时文件位置的决定和 **sys_get_temp_dir()** 的方式一致。

php://temp 的内存限制可通过添加 `/maxmemory:NN` 来控制，`NN` 是以字节为单位、保留在内存的最大数据量，超过则使用临时文件。



**示例 php://memory：**

```php
?php
// 创建一个新的 php://memory 流
$memoryStream = fopen('php://memory', 'r+');

// 写入一些数据到流中
fwrite($memoryStream, "Hello, World!");

// 将文件指针移到开头以便读取
rewind($memoryStream);

// 从流中读取数据
echo stream_get_contents($memoryStream); // 输出: Hello, World!

// 关闭流
fclose($memoryStream);
?>
```



**示例 php://temp：**

```php
<?php
// 创建一个新的 php://temp 流，并设置内存最大限制为 1 MB
$tempStream = fopen('php://temp/maxmemory:1048576', 'r+');

// 写入一些数据到流中
fwrite($tempStream, str_repeat("A", 1048576)); // 写入大约 1 MB 的数据
fwrite($tempStream, "Hello, World!"); // 再写入一些额外的数据

// 将文件指针移到开头以便读取
rewind($tempStream);

// 从流中读取数据
echo stream_get_contents($tempStream); // 输出: AAAAA...AAAHello, World!

// 关闭流
fclose($tempStream);
?>
```



### filter

php://filter 是一种元封装器， 设计用于**数据流**打开时的**筛选过滤**应用。

file_get_contents() 等函数，必须在读取全部内容后才能进行操作，如果搭配 **php://filter** 使用，则可以在读取的过程中进行文本数据的筛选过滤。

| 名称                        | 描述                                                         |
| :-------------------------- | :----------------------------------------------------------- |
| `resource=<要过滤的数据流>` | 这个参数是必须的。它指定了你要筛选过滤的数据流。             |
| `read=<读链的筛选列表>`     | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
| `write=<写链的筛选列表>`    | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
| `<；两个链的筛选列表>`      | 任何没有以 `read=` 或 `write=` 作前缀 的筛选器列表会视情况应用于读或写链。 |

`resource=<要过滤的数据流>` 也就是 file_get_contents() 函数要读取数据，可用是一个文件(**file://**)、HTTP(S)、ftp 或 data 。

`read=<读链的筛选列表>`，如果函数从resource 指定的数据流中读取数据，则应用 read 中定义的规则。

`write=<写链的筛选列表>`  ，如果函数写入数据到 resource  指定的数据流中，则应用 write 中定义的规则。



注意：resource 参数必须位于 php://filter 的末尾



**示例 #1 ：**

使用 **fopen** 打开一个**临时内存空间**，进行数据的读取和写入，在**写入数据**时会应用 **write** 规则，先将字符串**转为大写**，在进行 **base64 编码**，在**读取数据**时会应用 **read** 规则，将字符串进行 **base64 解码**。

```php
<?php

$fp = fopen("php://filter/write=string.toupper|convert.base64-encode/read=convert.base64-decode/resource=php://temp","w");

fwrite($fp,"hello world");

rewind($fp);

echo fread($fp,1024);

?>
```



**示例 #2 ：**

`<；两个链的筛选列表>`，当没有显示的指定 **read** 或 **write** 时，过滤规则将会**应用到 read 和 write 两种**操作。

在下面这个示例中，使了**convert.base64-encode**，**没有指定read还是write**，所以在fwrite**写入时会进行base64编码**，在fread**读取数据时会再次进行base64编码**。

```php
<?php

$fp = fopen("php://filter/convert.base64-encode/resource=php://temp","w");

fwrite($fp,"hello world");

rewind($fp);

echo fread($fp,1024);

?>
```



#### 过滤器

