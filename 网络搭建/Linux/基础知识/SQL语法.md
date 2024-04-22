# SQL基本语法



## 创建数据库

`create database [数据库名称];`

#### 创建数据库时，设置字符编码

`create database [数据库名称] default character set [字符编码] collate [字符编码校对规则];`

`create database test default character set utf8 collate utf8_bin;`

#### 常用字符编码介绍

在MySQL数据库中，default character set 设置的为字符编码，collate后面的设置就是校对规则（collation），它决定了如何比较和排序字符数据。

utf8_general_ci：这是一个不区分大小写的校对规则

utf8_bin：这是一个二进制校对规则，它将字符串中的每一个字符用二进制数据存储，并且在比较字符串时会区分大小写



## 创建数据表

`create table [数据表名称] ([列名1] [列名1类型],[列名2] [列名2类型],......);`

`create table user(id int,name varchar(255),password varchar(255),notes varchar(255));`

#### 设置数据表的字符编码

`create table [数据表名称] ([列名1] [列名1类型],[列名2] [列名2类型],......)default character set [字符编码] collate [字符编码校对规则];`

`create table user(id int,name varchar(255))default character set utf8 collate utf8_bin;`

此处设置的字符编码，作用于当前数据表的所有字符类型的列，包括以后新增的列，如何为不同的列设置不同的字符编码，将在**alter table（修改列名和类型）**中介绍。



## 修改列名和类型

#### 只修改列的类型

`alter table [数据表名称] modify [需要修改的列名] [列的新类型];`

`alter table user modify id varchar(255);`

#### 修改列的名称和类型

`alter table [数据表名称] change [需要修改的列名] [列的新名称] [列的新类型];`

`alter table user change name name_test int;`

#### 只修改列的名称

`alter table [数据表名称] change [需要修改的列名] [列的新名称] [列的新类型(此处输入有原类型)];`

`alter table user change id id_test int;`

#### 通过change只修改列的类型

`alter table [数据表名称] change [需要修改的列名] [列的新名称(这里输入原有名称)] [列的新类型];`

`alter table user change id id varchar(255);`



## 添加列和删除列

#### 添加新列

`alter table [数据表名称] add [新列名] [新列类型]`

`alter table user add password_2 varchar(255);`

####  添加列指定位置

##### 添加列到第一列

`alter table [数据表名称] add [新列名] [新列类型] first;`

`alter table user add password_2 varchar(255) first;`

##### 添加列到指定列的后面

`alter table [数据表名称] add [新列名] [新列类型] after [指定列];`

`alter table user add password_2 varchar(255) after password;`

#### 删除列

`alter table [数据表名称] drop [要删除的列];`

`alter table test drop password_2;`



## 为不同列设置不同的字符编码

`alter table [数据表名称] modify [列名] [列类型] character set [字符编码] collate [校对规则];`

`alter table user modify name varchar(255) character set utf8 collate utf8_bin;`

只有varchar(255)等存储字符类型的列才可以设置字符编码和校对规则，如int等其他类型则无法设置



## 查看数据库、数据表、列的字符编码和校对规则

#### 数据库

`show create database [数据库名称];`

`show create database test;`

#### 数据表

`show create table [数据表名称];`

`show create table user;`

#### 列

`show full columns from [数据表名称]`

`show full columns from user;`

##### 使用where查看指定的列

> where将在下面介绍

`show full columns from [数据表名称] where Field = '[列名]';`

`show full columns from user where Field = 'password';`



## 为数据表插入数据

#### 为所有列插入数据

`insert into [数据表名称] value([列1数据],[列2数据],[列3数据],.....);`

`insert into user value (1,'xiaoshae','xiaoshaePassword');`

> 字符串等数据需要使用引号

#### 为指定列插入数据

`insert into [数据表名称] ([指定列1],[指定列2],...) value([指定列1数据],[指定列2数据],......)`

`insert into user(id,password) value(1,'zhangSanPassword');`



## 查看数据中的数据

`select [指定列1],[指定列2],...... from [数据表名称];`

`select id,name from user;`

`select * from user;`

> *表示查看所有的列



#### distinct参数

> distinct 参数作用：如果有多个相同的数据，则只展示一个数据

`select distinct [指定列1],[指定列2],...... from [数据表名称];`

`select distinct id,name from user;`

`select distinct * from user;`



#### where子句

`select [指定列1],[指定列2],...... from [数据表名称] where [指定条件];`

`select id,name from user where id = 1;`

> 只展示id列值为1的数据



#### and 与 or

##### and

`select [指定列1],[指定列2],...... from [数据表名称] where [指定条件];`

`select id,name from user where id = 1 and name = 'ZhangSan';`

> 只展示id列值为1 且 name列的值为'ZhangSan' 的数据

##### or

`select [指定列1],[指定列2],...... from [数据表名称] where [指定条件];`

`select id,name from user where id = 1 or id = 2 ;`

> 只展示id列值为1 或者 id列值为2 的数据



#### and 与 or 的优先级

> 在MySQL中 and 的优先级高于 or，也就是说以下两条SQL语句是等价的

`select * from user where id > 0 and id < 100 or id > 1000 and id < 2000;`

`select * from user where (id > 0 and id < 100) or (id > 1000 and id < 2000);`



#### order by 关键字排序

`select id,name from user order by [列名1] [asc|desc],[列名2] [asc|desc],......`

`select id,name from user order by id asc;`

> 查询的数据按照id的值升序排序

`select id,name from user order by id desc;`

> 查询的数据按照id的值降序排序
>
> 默认进行升序排序



`select id,name from user order by id asc,name desc;`

> 查询的数据，先按照id的值降序排序，在按照name的值降序排序



#### union

MySQL UNION 操作符用于连接两个以上的 SELECT 语句的结果组合到一个结果集合，并去除重复的行。

UNION 操作符必须由两个或多个 SELECT 语句组成，每个 SELECT 语句的列数和对应位置的数据类型必须相同。

![image-20231211090102404](images/SQL%E8%AF%AD%E6%B3%95.assets/image-20231211090102404.png)



#### limit关键字

> limit关键字作用：无论select查询到多少条语句，最大只展示limit设置的条数

`select id,name from user limit 2;`

> 如果查询到的数据的条数小于等于2，则展示全部查询到的数据。如果大于2，则只展示2条。



select id,name from user limit 2,1;

查询到的所有数据，从第二条开始显示，总共显示一条。



#### in 关键字

in 关键字的作用：判断一个列的查询到的数据，是否存在于in指定的一堆数据

`select id,name from user where id in (1,3,5);`

```
mysql> select * from user;
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
|  2 | ZhangSan | ZhangSanPassword |
|  3 | Amaomao  | AmaomaoPassword  |
+----+----------+------------------+
3 rows in set (0.03 sec)

mysql> select * from user where id in (1,3,5);
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
|  3 | Amaomao  | AmaomaoPassword  |
+----+----------+------------------+
2 rows in set (0.03 sec)

mysql> select * from user where name in ('xiaoshae','ZhangSan');
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
|  2 | ZhangSan | ZhangSanPassword |
+----+----------+------------------+
2 rows in set (0.03 sec)
```



#### like 关键字

> like关键字作用：用于字符串的匹配
>
> '%'匹配多个字符   '_'匹配一个字符

```
mysql> select * from user;
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
|  2 | ZhangSan | ZhangSanPassword |
|  3 | Amaomao  | AmaomaoPassword  |
+----+----------+------------------+
3 rows in set (0.02 sec)

mysql> select * from user where name like '%xiao%';
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
+----+----------+------------------+
1 row in set (0.02 sec)

mysql> select * from user where name like '%x__o%';
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
+----+----------+------------------+
1 row in set (0.03 sec)
```



#### between 关键字

> between 关键字作用：指定一个范围
>
> 对于整数 1 and 3 表示 1 ~ 3，对于字符(日期等) 'a' and 'z' 表示 'a' <= x < 'z'(即，包括'a'不包括'z')

```
mysql> select * from user;
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
|  2 | ZhangSan | ZhangSanPassword |
|  3 | Amaomao  | AmaomaoPassword  |
+----+----------+------------------+
3 rows in set (0.03 sec)

mysql> select * from user where id between 1 and 2;
+----+----------+------------------+
| id | name     | password         |
+----+----------+------------------+
|  1 | xiaoshae | xiaoshaePassword |
|  2 | ZhangSan | ZhangSanPassword |
+----+----------+------------------+
2 rows in set (0.03 sec)
```



#### as 别名

as关键字：可以给列和数据表设置一个别名

```
mysql> select * from test;
+----+------+--------------+
| id | name | password     |
+----+------+--------------+
|  1 | test | testPassWord |
+----+------+--------------+
1 row in set (0.03 sec)

mysql> select a.name as a_name from test as a;
+--------+
| a_name |
+--------+
| test   |
+--------+
1 row in set (0.03 sec)
```





## 为数据表更新数据

`update [数据表名称] set [需要修改的列] = [数据] where [指定条件];`

`update user set name = 'ZhangSan' where password = 'ZhangSanPassword'：`

> 如果没有指定条件，将这一列中所有行的数据修改为指定数据



## 为数据表删除数据

`delete from [数据表名称] where [指定条件];`

`delete from user where id = 2;`

> 如果没有指定条件，将删除所有的数据