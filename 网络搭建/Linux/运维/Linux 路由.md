# Router

在 Linux 系统中，路由管理主要依赖 iproute2 工具集中的 **ip route** 命令。在深入探讨 **ip route** 命令的具体用法前，我们先来了解 **ip route help** 输出的命令参数格式。熟悉帮助信息中对参数的描述方式，将有助于更好地理解和掌握这一命令的使用技巧。



**ip route help** 命令输出的帮助信息中，部分内容如下。

```
ip route { add | del | change | append | replace } ROUTE

ROUTE := NODE_SPEC [ INFO_SPEC ]

NODE_SPEC := [ TYPE ] PREFIX [ tos TOS ]
             [ table TABLE_ID ] [ proto RTPROTO ]
             [ scope SCOPE ] [ metric METRIC ]
             [ ttl-propagate { enabled | disabled } ]

INFO_SPEC := { NH | nhid ID } OPTIONS FLAGS [ nexthop NH ]...

FAMILY := [ inet | inet6 | mpls | bridge | link ]
```



**ip route help** 的输出是一种命令行工具的语法描述，常用于 Linux 网络工具（如 **ip** 命令）的帮助信息。它采用了一种类似 BNF（巴科斯-诺尔范式）的形式，或者说是一种结构化的伪语法，用于清晰地描述命令的用法和参数。



参数的顺序**从左到右是完全固定的**，在下面的示例中，必须先出现 **route** 参数，才能出现 **add** 参数。

```
ip route add ...
```



`:=` 是一种定义符号，用于表示“被定义为”或“由以下部分组成”。

在下面示例中，ROUTE 参数由 **NODE_SPEC 和可选的 INFO_SPEC** 组成。

```
ROUTE := NODE_SPEC [ INFO_SPEC ]
```



大写参数是**占位符**或**抽象概念**，需要替换为具体的值或进一步分解为子参数。特别地，**ROUTE** 实际上会被替换为 **NODE_SPEC [ INFO_SPEC]**，因此下面的两个示例在语法上等价：

```
ip route { add | del | change | append | replace } ROUTE

ROUTE := NODE_SPEC [ INFO_SPEC ]
```

```
ip route { add | del | change | append | replace } NODE_SPEC [ INFO_SPEC ]
```



小写参数是**实际的关键字**或**命令中的固定字符串**，，用户需要按原样输入，直接在命令中使用。

```
ip route add ...
```

- 其中 **add** 是小写关键字，必须按原文输入。



**方括号 [ ]** 表示可选参数，即括号中的内容可以包含在命令中，也可以省略。

`[ INFO_SPEC ]` 表示 INFO_SPEC是可选的，命令在不包含该参数时仍然有效。

```
ROUTE := NODE_SPEC [ INFO_SPEC ]
```



方括号 [ ]，这些选项之间是互斥的，**可以选择一个，也可以完全不选择**（因为整个结构是可选的）。

下面示例表示可以选择 onlink 或 pervasive 参数，也可以不选择参数。

```
[ onlink | pervasive ]
```



**大括号 {}** 表示一组选项，这些选项之间是互斥的，必须从中选择一个。**竖线 |** 则表示“或”，用于分隔不同的选项。

在下面示例中，**{ add | del | change | append | replace }** 表示命令必须从 add、del、change、append 或 replace 中选择一个。

```
ip route { add | del | change | append | replace } ROUTE
```





**...（省略号）**表示可以重复前面的元素或模式，通常用于表示列表或序列可以有多个实例。

下面示例中，[ nexthop NH ] ... 表示可以有零个或多个 nexthop NH。

```
INFO_SPEC := { NH | nhid ID } OPTIONS FLAGS [ nexthop NH ] ...
```



**STRING**：表示一个用户提供的字符串，通常是名称或标识符。

**NUMBER**：表示一个用户提供的数字，通常是整数。

**ADDRESS**：表示 IP 地址（IPv4 或 IPv6）。

**PREFIX**：表示 IP 前缀（地址加掩码长度），如 10.0.0.0/24 或 default。

**BOOL**：表示布尔值，通常是 true 或 false，在某些参数中可能用其他形式（如 1 或 0）。

**TIME**：表示时间值，可能带单位（如 s, ms）。