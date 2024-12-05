# sessios

一个访问者访问你的 web 网站将被分配一个唯一的 id，就是所谓的会话 id。 这个 id 可以存储在用户端的一个 cookie 中，也可以通过 URL 进行传递。



## 基本流程

会话的工作流程很简单。

1. 当开始一个会话时，PHP 会尝试从请求中查找 Session ID （通常通过会话 cookie）， 如果请求中不包含 Session ID 信息，PHP 就会创建一个新的会话。
2. 会话开始之后，PHP 就会将会话中的数据设置到 `$_SESSION` 变量中。 当 PHP 停止的时候，它会自动读取 `$_SESSION` 中的内容，并将其进行序列化， 然后发送给会话保存处理程序来进行保存。



默认情况下，PHP 使用内置的文件会话保存处理程序（files）来完成会话的保存。 也可以通过配置项 `session.save_handler` 来修改所要采用的会话保存处理程序。 对于文件会话保存处理程序，会将会话数据保存到配置项 `session.save_path` 所指定的位置。



调用函数 session_start() 来手动开始一个会话。 如果配置项 **session.auto_start** 设置为1， 那么请求开始的时候，会话会自动开始。PHP 脚本执行完毕之后，会话会自动关闭。 同时，也可以通过调用函数 **session_write_close()** 来手动关闭会话。



## 传送会话ID

有两种方式用来传送会话 ID：

- Cookies
- URL 参数



会话模块支持这两种方式。 Cookie 方式相对好一些，但是用户可能在浏览器中关闭 Cookie，所以 第二种方案就是把会话 ID 直接并入到 URL 中，以保证会话 ID 的传送。

无需开发人员干预，PHP 就可以自动处理 URL 传送会话 ID 的场景。 如果启用了 `session.use_trans_sid` 选项， PHP 将会自动在相对 URI 中包含会话 ID。

> 注意: **arg_separator.output php.ini** 配置指令允许你自定义会话 ID 参数分隔符。 可以设定为 & 来保持和 XHTML 的一致性。
>



会话开始之后，可以使用 SID 常量。 如果客户端未提供会话 cookie，该常量的展开形式为 session_name=session_id， 反之，该常量为空字符串。因此，可以直接在 URL 中包含此常量的展开字符串而无需考虑会话 ID 的实际传送方式。



## 自定义会话处理程序

如果需要在数据库中或者以其他方式存储会话数据， 需要使用 session_set_save_handler() 函数来创建一系列用户级存储函数。 可以使用 SessionHandlerInterface 类 或者通过继承 SessionHandler 类扩展 PHP 的内置处理程序， 从而达到自定义会话保存机制的目的。

函数 session_set_save_handler() 的参数即为在会话生命周期内要调用的一组回调函数： open， read， write 以及 close。 还有一些回调函数被用来完成垃圾清理：destroy 用来删除会话， gc 用来进行周期性的垃圾收集。

因此，会话保存处理程序对于 PHP 而言是必需的。 默认情况下会使用内置的文件会话保存处理程序。 可以通过 session_set_save_handler() 函数来设置自定义会话保存处理程序。 一些 PHP 扩展也提供了内置的会话处理程序，例如：sqlite， memcache 以及 memcached， 可以通过配置项 session.save_handler 来使用它们。

会话开始的时候，PHP 会调用 open 处理程序，然后再调用 read 回调函数来读取内容，该回调函数返回已经经过编码的字符串。 然后 PHP 会将这个字符串解码，并且产生一个数组对象，然后保存至 $_SESSION 超级全局变量。

当 PHP 关闭的时候（或者调用了 session_write_close() 之后）， PHP 会对 $_SESSION 中的数据进行编码， 然后和会话 ID 一起传送给 write 回调函数。 write 回调函数调用完毕之后，PHP 内部将调用 close 回调函数。

销毁会话时，PHP 会调用 destroy 回调函数。

根据会话生命周期时间的设置，PHP 会不时地调用 gc 回调函数。 该函数会从持久化存储中删除超时的会话数据。 超时是指会话最后一次访问时间距离当前时间超过了 $lifetime 所指定的值。



## 常用函数

- session_start — 启动新会话或者重用现有会话
- session_status — 返回当前会话状态
- session_unset — 释放所有的会话变量
- session_save_path — 读取/设置当前会话的保存路径
- session_write_close — 写入会话数据并结束会话
- session_id — 获取/设置当前会话 ID
- session_name — 读取/设置会话名称



### session_start 

**session_start()** 会创建新会话或者重用现有会话。 如果通过 GET 或者 POST 方式，或者使用 cookie 提交了会话 ID， 则会重用现有会话。



### session_status

```php
session_status(): int
```

**session_status()** 被用于返回当前会话状态。



**返回值**

- **PHP_SESSION_DISABLED** 会话是被禁用的。
- **PHP_SESSION_NONE** 会话是启用的，但不存在当前会话。
- **PHP_SESSION_ACTIVE** 会话是启用的，而且存在当前会话。



### session_unset 

**session_unset()** 会释放当前会话注册的所有会话变量。

```php
session_unset(): bool
```



**返回值**

成功时返回 true， 或者在失败时返回 false。



**注意：**

- 如果使用的是 `$_SESSION`，请使用 `unset()` 去 注销会话变量，即 `unset($_SESSION['varname']);`。
    - 请不要使用 `unset($_SESSION)` 来释放整个 `$_SESSION`， 因为它将会禁用通过全局 `$_SESSION` 去注册会话变量。
- `session_unset()` 的使用与 `$_SESSION = []` 相同。
    - 仅当 session 处于活动状态时，此函数才能起作用。如果 session 尚未启动或已经销毁，它将无法清除 `$_SESSION` 数组。即使 session 不活跃，请使用 `$_SESSION = []` 来删除所有 session 变量。



### session_save_path 

**session_save_path()** 返回当前会话的保存路径。

```php
session_save_path(?string $path = null): string|false
```



**参数**

path：指定会话数据保存的路径。如果已经指定且不为 **null**，保存数据的路径将会改变。 必须在调用 **session_start()** 函数之前调用 **session_save_path()** 函数。

> **注意**：在某些操作系统上，建议使用可以高效处理 大量小尺寸文件的文件系统上的路径来保存会话数据。



**返回值**

返回保存会话数据的路径， 或者在失败时返回 false。



### session_write_close

**session_write_close** 结束当前会话并存储会话数据。

```php
session_write_close(): bool
```

会话数据通常会在您的脚本终止后自动保存，无需显式调用 `session_write_close()` 函数。但是，为了防止并发写入，会话数据在处理过程中是被锁定的，这意味着同一时间只有一个脚本可以操作一个会话。当使用框架集（framesets）与会话一起时，由于这种锁定机制，您可能会遇到框架逐一加载的情况。

在调用了 `session_write_close()` 之后，您将不能再对会话数据进行任何修改。



**返回值**

成功时返回 true， 或者在失败时返回 false。



### session_id

**session_id()** 可以用来获取/设置 当前会话 ID。

```
session_id(?string $id = null): string|false
```



**参数**

id
如果指定了 id 且不为 null， 则使用指定值作为会话 ID。 必须在调用 **session_start()** 函数之前调用 **session_id()** 函数。 不同的会话处理程序对于会话 ID 中可以使用的字符有不同的限制。 例如文件会话处理程序仅允许会话 ID 中使用以下字符：[a-zA-Z0-9,-]

> 注意：如果使用 cookie 方式传送会话 ID，并且指定了 id 参数， 在调用 session_start() 之后都会向客户端发送新的 cookie， 无论当前的会话 ID 和新指定的会话 ID 是否相同。



**返回值**

**session_id()** 返回当前会话ID。 如果当前没有会话，则返回空字符串（`""`）。失败时返回 **`false`**。



### session_name

**session_name()** 函数返回当前会话名称。 如果指定 `name` 参数， **session_name()** 函数会更新会话名称， 并返回 *原来的* 会话名称。

```php
session_name(?string $name = null): string|false
```



如果使用 **name** 指定了新字符串作为会话 cookie 的名字， session_name() 函数会修改 HTTP 响应中的 cookie （如果启用了 **session.use_trans_sid**，还会输出会话 cookie 的内容）。

一旦在 HTTP 响应中发送了 cookie 的内容之后， 调用 **session_name()** 函数会产生 **E_WARNING**。

所以，一定要在调用 **session_start()** 函数之前 调用此函数。



**参数**

name

用在 cookie 或者 URL 中的会话名称， 例如：PHPSESSID。 只能使用字母和数字作为会话名称，建议尽可能的短一些， 并且是望文知意的名字（对于启用了 cookie 警告的用户来说，方便其判断是否要允许此 cookie）。 如果指定了 **name** 且不为 **null****，** 那么当前会话也会使用指定值作为名称。

> 注意：会话名称至少需要一个字母，不能全部都使用数字， 否则，每次都会生成一个新的会话 ID。



**返回值**

返回当前会话名称。如果指定 `name` 参数，那么此函数会更新会话名称，并且 返回 *原来的* 会话名称， 或者在失败时返回 **`false`**。





## 示例

### 示例 #1 在 $_SESSION 中注册变量。

```php
<?php
session_start();

if (!isset($_SESSION['count'])) {
	$_SESSION['count'] = 0;
} else {
	$_SESSION['count']++;
}
?>
```



### 示例 #2 从 $_SESSION 中反注册变量。

```php
<?php
    
	session_start();
	unset($_SESSION['count']);

?>
```

