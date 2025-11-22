# DD

`dd` 是 Linux/Unix 系统中一个非常强大且底层的工具，主要用于**复制文件**并在复制过程中对数据进行**转换和格式化**。由于它直接对扇区或字节进行操作，它常用于备份引导扇区、克隆磁盘或创建空文件。



## 参数

### 输入输出

**if=FILE (Input File)**

指定输入文件。如果不指定，默认从标准输入（stdin）读取。



**of=FILE (Output File)**

指定输出文件。如果不指定，默认写出到标准输出（stdout）。



### 块大小与计数

**bs=BYTES (Block Size)**

同时设置读取（ibs）和写入（obs）的块大小为 BYTES 字节（默认：512）。此选项会覆盖 ibs 和 obs 的设置。这是控制复制速度和效率的关键参数。



**count=N (Block Count)**

仅复制 N 个输入块。总复制大小由 `N` 乘以 `ibs`（或 `bs`）决定。若 `N` 以 'B' 结尾，则表示字节数而非块数。



**ibs=BYTES (Input Block Size)**

每次读取 BYTES 字节（默认：512）。如果不指定，默认与 `bs` 相同。



**obs=BYTES (Output Block Size)**

每次写入 BYTES 字节（默认：512）。如果不指定，默认与 `bs` 相同。



**seek=N (or oseek=N)**

在写入之前，跳过输出文件开头的 N 个 `obs` 大小的块。



**skip=N (or iseek=N)**

在读取之前，跳过输入文件开头的 N 个 `ibs` 大小的块。



### 转换

**cbs=BYTES (Conversion Block Size)**

每次转换 BYTES 字节。此选项仅在使用了需要块转换的 `conv` 选项（如 `block`, `unblock`, `ascii` 等）时生效。



**conv=CONVS (Conversions)**

按照逗号分隔的符号列表对文件进行转换。可用的符号包括：

- `ascii`: 将 EBCDIC 编码转换为 ASCII。
- `ebcdic`: 将 ASCII 编码转换为 EBCDIC。
- `ibm`: 将 ASCII 编码转换为另一种 EBCDIC。
- `block`: 将以换行符终止的记录用空格填充至 `cbs` 大小。
- `unblock`: 将 `cbs` 大小记录中的尾随空格替换为换行符。
- `lcase`: 将大写字母转换为小写。
- `ucase`: 将小写字母转换为大写。
- `sparse`: 尝试跳过输出而不是写入全 NUL（空字符）的块（创建稀疏文件）。
- `swab`: 交换每一对输入字节（用于解决字节序问题）。
- `sync`: 用 NUL（空字符）将每个输入块填充至 `ibs` 大小；若与 `block` 或 `unblock` 一起使用，则用空格填充。
- `excl`: 如果输出文件已经存在，则操作失败。
- `nocreat`: 不创建输出文件（如果文件不存在则失败）。
- `notrunc`: 不截断输出文件（即不覆盖整个文件，只替换写入的部分）。
- `noerror`: 读取发生错误后继续进行。
- `fdatasync`: 在结束前将输出文件数据物理写入磁盘。
- `fsync`: 同上，但也写入元数据。



### 其他

**iflag=FLAGS (Input Flags)**

按照逗号分隔的符号列表控制读取行为。可用的符号包括：

- `append`: 追加模式（通常用于输出，但在 iflag 中意义有限）。
- `direct`: 使用直接 I/O 读取数据（绕过系统缓存）。
- `directory`: 除非是目录，否则失败。
- `dsync`: 使用同步 I/O 读取数据。
- `sync`: 同上，但也包含元数据。
- `fullblock`: 累积完整的输入块（防止从管道读取时因数据不足而提前返回）。
- `nonblock`: 使用非阻塞 I/O。
- `noatime`: 不更新访问时间。
- `nocache`: 请求丢弃缓存。
- `noctty`: 不从文件分配控制终端。
- `nofollow`: 不跟随符号链接。



**oflag=FLAGS (Output Flags)**

按照逗号分隔的符号列表控制写入行为。可用的符号参考 `iflag`，其中 `append`（追加模式）和 `direct`（绕过缓存写入）在输出中尤为常用。



**status=LEVEL**

控制打印到标准错误（stderr）的信息级别。

- `none`: 仅打印错误消息，抑制所有其他信息。
- `noxfer`: 抑制最终的传输统计信息。
- `progress`: 显示周期性的传输统计信息（如进度条、速度、剩余时间）。



**--help**

显示帮助信息并退出。



**--version**

输出版本信息并退出。



**N 和 BYTES 的单位后缀**

上述参数中的数值 `N` 和 `BYTES` 可以跟随以下乘数后缀：

- `c` = 1
- `w` = 2
- `b` = 512
- `kB` = 1000
- `K` = 1024
- `MB` = 1000*1000
- `M` = 1024*1024
- `GB`, `G`, `TB`, `T` 等以此类推。
- 此外，支持二进制前缀如 `KiB`=K, `MiB`=M 等。





## 典型示例

### 单位后缀

**示例 1：使用二进制后缀 (推荐)**

这是计算机内存和文件系统（如 Linux `ls -lh`）默认的计算方式（1024进制）。

```
dd if=/dev/zero of=file_binary bs=1G count=1
```

```
dd if=/dev/zero of=file_binary bs=1GiB count=1
```

**解析**：`bs=1G` 或 `bs=1GiB` 代表 1×1024×1024×1024 字节。



**示例 2：使用十进制后缀**

这是硬盘厂商标注容量（如购买 1TB 硬盘）或网络速度常用的计算方式（1000进制）。

```
dd if=/dev/zero of=file_decimal bs=1GB count=1
```

**解析**：`bs=1GB` 代表 1×1000×1000×1000 字节。



**示例 3：使用扇区单位 (`b`)**

```
dd if=boot.img of=/dev/sdb bs=1b count=1
```

**解析**：`bs=1b` 等于 `bs=512` 字节。通常用于只备份磁盘的前 512 字节（MBR 引导记录）。



**示例 4：在 `count` 中使用后缀**

```
dd if=/dev/urandom of=random_data bs=1M count=2k
```

**解析**：`bs=1M` = 单次读写 1 MiB (1024 * 1024 字节)。`count=2k` = 复制 2048 个块 (2×1024)。**总大小** 2048 MiB (即 2 GiB)。

