# wireshark使用设置

参考链接:https://www.youtube.com/watch?v=OU-A2EmVrKQ&list=PLW8bTPfXNGdC5Co0VnBK1yVzAwSSphzpJ



# 规则配置文件

在wireshark的右下角可以管新建、删除、管理配置文件，配置文件保存了wireshark的设置信息，例如：着色器、过滤规则等。

![image-20231129165142360](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129165142360.png)



# 页面布局



## 总体布局

在Windows中，选择菜单中的编辑，选择首选项，选择布局，即可设置页面的布局。

packet diagram 则表示使用 数据包图标 的方式来展示信息。

![image-20231129165403798](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129165403798.png)



## 数据包图标

在 数据包图标 中选中，在分组详情中也会选中对应的。

![image-20231129165554741](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129165554741.png)



默认情况下，**数据包图标**不会显示具体的参数信息，在**数据包图标**中**右击**，选择"**show field values**"即可显示

![image-20231129165700449](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129165700449.png)



## 列信息

在编辑，首选项，外观，列。在这里可以设置列的名称，以及所显示的信息。

可以启用，关闭列。添加，删除列。

![image-20231129170118129](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129170118129.png)





# 着色器

单击此处，即可快速开启或者关闭着色器。

![image-20231129170355313](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129170355313.png)



单机菜单中的"视图"，选中"着色器规则"，即可打开着色器规则的对话框

可以为添加、删除，启用、关闭着色器规则。

设置规则的前景色和背景色。

![image-20231129170622786](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129170622786.png)





最上方的优先级最高，最下方的优先级最低。

例如：这样的两条规则

如果一个数据包的ack为1，那么这个数据包肯定也是一个tcp数据包。

此时，前景色会显示为红色，因为tck.ack == 1规则的优先级高于tcp

![image-20231129171000919](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129171000919.png)



# 快速新增列

在分组详情中选中一个字段，右击选中"应用为列"。

就会快速新增一个列，显示该字段的名称



设置前

新增一个列，显示的信息为tcp包中源端口的信息

![image-20231129171431096](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129171431096.png)



设置后（两图所选的包不同）

多了一个列，source port。显示tcp端口中的源端口。

![image-20231129171722880](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129171722880.png)



# 快速设置过滤器

在分组详情中选中一个字段，右击选中"作为过滤器应用"中的"选中"，即可快速添加一个过滤器规则，进行筛选。

![image-20231129172001372](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129172001372.png)



这样就会筛选目标IP为172.16.1.104的数据包了。

如果这条过滤规则是一条经常会用到的规则。

单击左边的"+"，为这条过滤器设置一个名称，单击确定。

![image-20231129172208443](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129172208443.png)

"+"号后面就多了一个按钮，按钮名称就是设置的标签，单击按钮就可以应用这条过滤规则。

![image-20231129172342599](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231129172342599.png)



## matches

matches 允许你使用正则表达式来过滤流量

```
dns.cname matches ".cn"
```



## tls client hello

只显示 tls client hello 的流量

```
tls.handshake.type == 1
```



# 接口捕获设置

![image-20231130094830632](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231130094830632.png)



在"wireshark捕获选项"对话框中，单击"管理接口"，即可对本地接口进行设置，是否启用该接口。

![image-20231130094917179](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231130094917179.png)



建议为所有的接口启用混杂模式，这样wireshark不仅会捕获往返于自身的流量，还捕获彼此之间单播流量的其他机器

![image-20231130095206487](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231130095206487.png)



在输出选项中，可以设置捕获流量保存的文件位置。

可以设置单个文件的最大字节数，这里设置为500MB

如果一个文件到达500MB，则会创建一个新的文件，来保存后续捕获的数据。

设置为10表示最多有10个500MB的文件，如果到达了10个文件，将会删除第一个文件，循环往复。

![image-20231130103238659](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231130103238659.png)



# Dumpcap 捕获数据包

翻译自**Dumpcap[2023-11-30]手册**部分内容

官方手册链接**[2023-11-30]**:https://www.wireshark.org/docs/man-pages/dumpcap.html



## 描述

**Dumpcap**是一个捕获网络流量的工具，它允许**实时捕获网络数据包**并将**数据包写入文件**。默认的文件格式为**pcapng**，当指定`-P`选项时，将使用**pcap**文件格式格式。

如果没有指定网络接口，将从第一个可用网络接口捕获流量，并将接收到的**原始数据包**和及**数据包的时间戳**写入文件。

如果没有使用`-w`参数**指定文件存放位置**，将创建新的文件，**文件名称随机**。

数据包捕获是使用 pcap 库执行的。捕获过滤器语法遵循 pcap 库的规则。



## 选项

### -P

将文件另存为 pcap 而不是默认的 pcapng。在需要 pcapng 的情况下，例如从多个接口捕获，此选项将被覆盖。



### -a|--autostop <自动停止条件>

指定**何时停止捕获网络流量**。标准的形式为 `test:value`，其中 test 是以下之一：

- `duration:value`
    - 经过 **value 秒后停止捕获**。允许使用浮点值（例如 0.5）
- `files:value`
    - 捕获 **value 个文件后停止捕获**。
- `filesize:value`
    - 在文件大小达到 `value kB` 后停止捕获。
    - 如果此选项与 `-b` 选项一起使用，**达到文件大小**时将**停止写入当前文件**，并切换到下一个文件写入。
- `packet:value`
    -  当捕获的数据包达到 value 个时停止写入。作用与 -c <捕获数据包计数> 相同。



### -c <捕获数据包计数>

设置捕获 **value 个文件后停止捕获**。。作用与 `-a packet:value` 相同。



### -b|--ring-buffer <捕获环形缓冲区选项>

每个 `-b` 参数仅指定一个子参数；要指定两个子参数，必须要有两个 `-b` 参数。

```
-b duration:3600 -b files:100
```



将捕获的数据包**写入多个文件**。当第一个文件填满时，将切换写入下一个文件，依此类推。

创建的文件，文件名基于 `-w` 选项给出的文件名、文件编号以及创建日期和时间。

```
outfile_00001_20230714120117.pcapng
outfile_00002_20230714120523.pcapng
outfile_00003_20230714120853.pcapng
......
```



标准的形式为 `key:value`，其中 key 是以下之一：

- `duration:value`
    - 经过 **value 秒后停止当前文件的保存**，切换到下一个文件保存数据包，即使当前**文件未完全填满**（未达到指定的文件大小）。允许使用浮点值（例如 0.5）。
- `files:value`
    - 指定**文件最大数量**。在写入 value 个文件后从第一个文件重新开始（形成环形缓冲区）。该值必须小于 100000。
    - 使用大量文件时应小心：某些文件系统不能很好地处理单个目录中的多个文件。
    - 文件标准要求指定持续时间、间隔或文件大小来控制何时转到下一个文件。
- `filesize:value`
    - 指定单个文件的大小，在达到 `value kB` 大小后切换到下一个文件。
    - 文件大小的最大值限制为 2 GiB（2048 MiB = 2,097,152 KiB）。
- `interval:value`
    - 经过 value 秒后切换到下一个文件。
    - 例如：`-b interval:value` ，一个小时切换一次文件
- `packet:value`
    - 在文件捕获 value 个数据包后，切换到下一个文件



# Time

## DataPack

![image-20231204110822058](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204110822058.png)

- Time表示从开始捕获的数据包中，第一个数据包到当前数据包所经过的时间。
- Delate表示上个一个数据包，到当前数据包所经过的时间。



"`frame.time_delta`"和"`frame.time_delta_displayed`"这两个字段的区别：

假设有四个帧，帧1、帧2、帧3和帧4。如果你没有应用显示过滤器，则两个字段的值是一样的。

如果应用了显示过滤器，只显示帧1和帧3

"`frame.time_delta`" 帧3的Delta显示的是，**帧2（上一帧）到帧3（当前帧）所经过的时间**，即使帧2被过滤了。

"`frame.time_delta_displayed`"帧3的Delta显示的是，**帧1到帧3（当前帧）所经过的时间**，因为帧2被过滤了。



## 设置Time布局样式

视图菜单—>时间显示格式

![image-20231204112002238](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204112002238.png)



这里选择为"时间(xxxxxxxx)"

![image-20231204112138205](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204112138205.png)



## TCP Stram Time

TCP流（TCP Stream）是指在TCP协议中，它将数据以字节流的形式发送出去，接收者也以字节流的形式接收数据。这种方式被称为流，因为在传输过程中，它保持了数据流的连续性。

在具体的网络报文层面，一个TCP流对应的就是一个五元组：传输协议类型、源IP、源端口、目的IP、目的端口。或者说相同的五元组构成一个TCP流。



这五个元素都包含在IP报文中，所以在解析抓包文件时，Wireshark可以通过五元组知道每个报文所属的TCP流。这也是为什么我们可以在Wireshark里，用Follow TCP Stream的方法，找到报文所在的TCP流。

![image-20231204112500683](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204112500683.png)



- `"Time since first frame in this TCP stream"`表示从TCP流的第一帧开始到当前帧的时间差。这个值是Wireshark基于当前帧和第一帧的时间计算出来的。
- `"Time since previous frame in this TCP stream"`表示从TCP流的上一帧到当前帧的时间差。这个值是Wireshark基于当前帧和上一帧的时间计算出来的。



# 统计

Wireshark中有一个统计功能，可以对当前文件的所有数据包进行一个详细的统计。



"统计"菜单中选择绘画，即可打开统计选项卡

![image-20231204123356976](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204123356976.png)



## 数据链路层视角

![image-20231204123928060](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204123928060.png)

- 整个网络中只有两台主机进行通信。
- 主机A的MAC地址：08:00:27:01:39:F0
- 主机B的MAC地址：52:54:00:12:35:02



其他信息：两台主机发送数据包的总数（以及互相发数据包的数量）、两台主机发送的数据总字节数（以及互相发送字节数的数量）、两台主机通讯持续时间。



## 网络层视角IPv4/IPv6

> 由于IPv4与IPv6内容基本相同，此处仅介绍IPv4部分

![image-20231204125204160](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204125204160.png)

- 源IP地址与目的IP地址
- 数据包数量
- 流量字节数
- 持续时间



通过图标的方式更准确的了解互相通讯的开始时间、持续时间

![image-20231204125603639](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204125603639.png)

通过对字节数的逆序排序，可以迅速查找出传输字节数在网络中大的会话，很有可能是在传输文件

![image-20231204125946053](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204125946053.png)



## TCP传输层视角

![image-20231204125320542](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204125320542.png)

- 源IP地址与目的IP地址
- 源端口与目的端口
- 数据流ID
- 数据包数量
- 流量字节数
- 持续时间



在传输层视图中进行分析，很容易可以找到网络中是否存在端口扫描等内网渗透攻击。

![image-20231204130136125](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204130136125.png)

![image-20231204130112347](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204130112347.png)



## 快速过滤

可以在会话对话框中快速的进行数据包显示过滤。



### IPv4

仅显示指定的两个IP地址互相发送的数据包。

![image-20231204130419464](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204130419464.png)

![image-20231204130511430](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204130511430.png)



### TCP Stream

仅显示指定的两个IP地址（指令的两个端口，TCP数据流）发送的数据包。

![image-20231204130648571](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204130648571.png)

![image-20231204130749763](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204130749763.png)



# 启用TCP重组

在传输层中的TCP协议中，一个数据包的大小可能无法一次性全部传输，这涉及到TCP分段和TCP重组，WireShark中默认开启了TCP重组，也就是说WireShark会将同一个TCP Stream中由于分段产生的数据包组合成一个数据包进行显示。



在"分组详情"中右击Transmission Control Protocol，勾选/取消"Allow subdissector to reassemble TCP streams"，可以开启/关闭，WiresShark重组TCP数据包（**默认开启**）。

![image-20231204132500178](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204132500178.png)





## 关闭重组TCP数据包

![image-20231204133048485](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204133048485.png)



## 开启重组TCP数据包

![image-20231204133132092](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204133132092.png)



# 提取网络中传输的文件

WireShark可以提取部分协议中传输的问题，通过分析数据包发现网络中通过HTTP协议传输了一个PNG格式的图片文件。

![image-20231204133311035](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204133311035.png)



在文件菜单中，选择""导出对象"，在选择"HTTP"

![image-20231204133455589](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204133455589.png)



选中想要到导出的文件，单击"保存"按钮即可导出。

![image-20231204133554184](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204133554184.png)



# 文本视图查看TCP Stream

选中TCP Stream数据包，右击选中"追踪流"中的"TCP Stream"

![image-20231204133802222](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204133802222.png)



以文本方式查看TCP Stream中传输的数据，通过此方式导出二进制数据，使用其他的工具进行分析，从而提取出Wire Shark不支持导出的文件。

![image-20231204133943576](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231204133943576.png)



# GeoIP

为WireShark中的IP获取地理位置信息，即可以方便的统计IP所在的地区。

文件下载链接：

下载后效果

![image-20231205091241856](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231205091241856.png)

解压三个压缩包，将文件保存到同一个文件夹中

![image-20231205091329179](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231205091329179.png)



在WireShark中添加该文件夹路径，保存退出，重启WireShark

![image-20231205091449964](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231205091449964.png)

![image-20231205091515223](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231205091515223.png)



## 数据包查看地址

在数据包中已经可以查看地址了

![image-20231205091611291](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231205091611291.png)



## 统计

在统计"菜单"的，"端点"选项中，也可以查看位置信息。

![image-20231205091701908](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231205091701908.png)



## MAP

在浏览器中更加直观的查看位置信息。

![image-20231205091816406](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20231205091816406.png)

![image-20240103123656976](images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20240103123656976.png)



# tls 解密

导入 TLS 私钥进行解密

![image-20241020100417787](./images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/image-20241020100417787.png)

![img](./images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/1497295-20190913155902948-1727782905.png)



## SSLKEYLOGFILE

`SSLKEYLOGFILE` 是一个环境变量，它通常用于指定一个文件路径，该文件将记录SSL/TLS会话密钥。

当使用某些支持这个功能的浏览器或工具时（例如Firefox、Chrome等），设置这个环境变量可以让你保存加密通信的主密钥到指定的日志文件中。

在 Wireshark 中指定该文件的位置，可以使用该文件的记录的主密钥自动解密TLS流量。

![img](./images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/1497295-20190913161459489-1232507597.png)

![img](./images/WireShark%E5%9F%BA%E7%A1%80%E8%AE%BE%E7%BD%AE.assets/1497295-20190913163859908-246308769.png)