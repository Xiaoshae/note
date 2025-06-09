# postgresql

PostgreSQL 使用客户端/服务器模型。PostgreSQL 会话包含以下协作进程（程序）

- 一个服务器进程，它管理数据库文件，接受客户端应用程序发出的数据库连接并代表客户端执行数据库操作。数据库服务器程序称为 `postgres`。
- 想要执行数据库操作的用户客户端（前端）应用程序。客户端应用程序的本质可能差异很大：客户端可能是面向文本的工具、图形应用程序、访问数据库以显示网页的 Web 服务器，或专用数据库维护工具。某些客户端应用程序随 PostgreSQL 发行；大多数由用户开发。

与客户端/服务器应用程序典型情况类似，客户端和服务器可以位于不同的主机上。在这种情况下，它们通过 TCP/IP 网络连接进行通信。您应该记住这一点，因为在客户端机上可以访问的文件可能无法在数据库服务器机上访问（或可能只能使用不同的文件名访问）。

PostgreSQL 服务器可以处理来自客户端的多个并行连接。为了实现这一点，它为每个连接启动（“派生”）一个新进程。从那一点开始，客户端和新的服务器进程会在没有原始 `postgres` 进程干预的情况下进行通信。因此，服务器进程常驻运行，等待客户端连接，而客户端和关联服务器进程则会来来去去。（所有这一切当然对用户不可见。我们在这里提到它只是为了完整性。）





## 基本命令

查看能否访问数据库服务器的第一个测试是尝试创建一个数据库。要创建一个新数据库（本例中名为`mydb`），请使用以下命令：

```
$ createdb mydb
```

通过命令行工具 **createdb** 创建数据库和通过 SQL 语法 **CREATE DATABASE** 创建数据库在功能上是等价的，因为 **createdb** 实际上是 **CREATE DATABASE** 的命令行封装。

如果这没有产生任何响应，则此步骤成功。



使用 psql 进入数据库

```
$ psql mydb
```



在 `psql` 中，您将收到以下消息

```
psql (17.1)
Type "help" for help.

mydb=>
```



最后一行也可能是

```
mydb=#
```

这意味着您是一个数据库超级用户，如果您自己安装了 PostgreSQL 实例，很可能就是这种情况。成为超级用户意味着不受访问控制的影响。



`psql` 程序有许多不是 SQL 命令的内部命令。它们以反斜杠字符 “`\`” 开头。例如，您可以通过键入以下命令获得 PostgreSQL 中各种命令的语法帮助 SQL命令

```
mydb=> \h
```



要退出 `psql`，请键入以下命令，`psql` 将退出并返回到您的命令行 shell。（有关更多内部命令，请在 `psql` 提示符处键入 `\?`。）

```
mydb=> \q
```



## 表

PostgreSQL 是一款功能强大的**关系数据库管理系统（RDBMS）**，专门用于管理以**关系**形式存储的数据。这里的“关系”实际上是数学术语，对应我们日常所说的**表**。

在 PostgreSQL 中，每个表都是一个由**行**组成的命名集合。表中的每一行都包含一组相同的**列**，每列都有其特定的数据类型。需要注意的是，虽然列的顺序在每行中是固定的，但 SQL 并不保证表中行的存储顺序（尽管可以通过查询对结果进行排序显示）。





### 创建

通过指定表名及其所有列名和类型，可以创建一个新表

```
CREATE TABLE weather (
    city            varchar(80),
    temp_lo         int,           -- low temperature
    temp_hi         int,           -- high temperature
    prcp            real,          -- precipitation
    date            date
);
```

你可以将分好行的以下语句输入到`psql`中。 `psql`会知道指令直到分号出现之前不会结束。

SQL指令使用空格（即空格键、制表符和新行）时非常自由。这意味着你可以输入与上述不同的指令对齐方式，甚至全部输入到一行中。两个破折号 (“`--`”) 表示注释。不管后面是什么，都会一直忽略到行末。SQL在关键字和标识符上不区分大小写，除非标识符用双引号引起来以保留大小写（上述没有用）。



第二个示例将存储城市及其相关的地理位置

```
CREATE TABLE cities (
    name            varchar(80),
    location        point
);
```

`point` 类型是一个 PostgreSQL特定数据类型的示例。



最后，应该提一下，如果你不再需要一个表或者想要以不同的方式重新创建它，可以使用以下指令来删除它

```
DROP TABLE tablename;
```



### 插入

使用 `INSERT` 语句来使用行填充表

```
INSERT INTO weather VALUES ('San Francisco', 46, 50, 0.25, '1994-11-27');
```

在 SQL 的 INSERT 语句中，对于非数值类型的列值（如字符串、日期等），通常需要用单引号 (') 括起来，而数值类型（整数、小数等）则不需要。



`point` 类型需要坐标对作为输入，如下所示：

```
INSERT INTO cities VALUES ('San Francisco', '(-194.0, 53.0)');
```

这种语法要求您记住列的顺序



另一种语法允许您明确列出：。

```
INSERT INTO weather (city, temp_lo, temp_hi, prcp, date)
    VALUES ('San Francisco', 43, 57, 0.0, '1994-11-29');
```



如果您愿意，可以按不同的顺序列出这些列，甚至可以省略一些列，例如，如果降水量未知。

```
INSERT INTO weather (date, city, temp_hi, temp_lo)
    VALUES ('1994-11-29', 'Hayward', 54, 37);
```

许多开发人员认为显式列出列比隐式依赖顺序更好。



### 查询

SQL **SELECT** 语句用于执行查询操作。此语句被分为一个**选择列表（列出要返回的列的部分）**、一个**表格列表（列出要从中检索数据表的的部分）**和一个**可选条件（指定任何限制的部分）**。

```
SELECT 列名1, 列名2, ... FROM 表名 [WHERE 条件] [ORDER BY 排序字段] [DISTINCT];
```



检索表格 `weather` 的所有行，此处 `*` 是 “所有列” 的简写。

```
SELECT * FROM weather;
```

```
SELECT city, temp_lo, temp_hi, prcp, date FROM weather;
```

虽然 `SELECT *` 对于即兴查询很有用，但它被广泛认为是开发代码中的糟糕风格，因为向表中添加列会更改结果。



可以**在选择列表中编写表达式**，而不仅仅是编写简单的列引用。

```
SELECT city, (temp_hi+temp_lo)/2 AS temp_avg, date FROM weather;
```

```
     city      | temp_avg |    date
---------------+----------+------------
 San Francisco |       48 | 1994-11-27
 San Francisco |       50 | 1994-11-29
 Hayward       |       45 | 1994-11-29
(3 rows)
```

注意 `AS` 子句如何用于重新标记输出列。（`AS` 子句是可选的。）



可以通过添加一个指定所需行的 `WHERE` 子句来““限定””查询。 `WHERE` 子句包含一个布尔值（真值）表达式，并且仅返回布尔表达式为真的行。限定中允许使用常见的布尔运算符（`AND`、`OR` 和 `NOT`）。

检索 weather 表中**旧金山下雨天的记录**

```
SELECT * FROM weather
    WHERE city = 'San Francisco' AND prcp > 0.0;
```

```
     city      | temp_lo | temp_hi | prcp |    date
---------------+---------+---------+------+------------
 San Francisco |      46 |      50 | 0.25 | 1994-11-27
(1 row)
```



通过 **ORDER BY** 子句指定排序顺序来返回查询结果，以下查询会按照 **city** 字段升序排列数据：

```
SELECT * FROM weather
    ORDER BY city;
```

```
     city      | temp_lo | temp_hi | prcp |    date
---------------+---------+---------+------+------------
 Hayward       |      37 |      54 |      | 1994-11-29
 San Francisco |      43 |      57 |    0 | 1994-11-29
 San Francisco |      46 |      50 | 0.25 | 1994-11-27
```



如果排序条件未完全指定（例如仅按 **city** 排序），数据库可能会以任意顺序返回相同 **city** 值的行（如示例中的两行“San Francisco”数据）。

为确保结果完全一致，您可以进一步细化排序条件。例如，以下查询会先按 **city** 排序，再按 **temp_lo** 排序，从而保证结果的可预测性：

```
SELECT * FROM weather
    ORDER BY city, temp_lo;
```



通过 `DISTINCT` 关键字从查询结果中**去除重复行**

```
SELECT DISTINCT city
    FROM weather;
```

```
     city
---------------
 Hayward
 San Francisco
(2 rows)
```



**返回结果的顺序可能不一致**。若希望确保结果按特定顺序排列，可以结合 `ORDER BY` 使用：

```
SELECT DISTINCT city
FROM weather
ORDER BY city;
```



在某些数据库系统（包括旧版 PostgreSQL）中，`DISTINCT` 的实现可能会**自动对结果进行排序**，因此无需额外使用 `ORDER BY`。然而，**SQL 标准并未强制要求这一行为**，且**当前版本的 PostgreSQL 并不保证 `DISTINCT` 会排序结果**。