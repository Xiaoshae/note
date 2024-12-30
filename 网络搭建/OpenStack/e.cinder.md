# Cinder

1. 创建一个 Cinder

命名为 cinder1，大小为 10 GB

```
cinder create --display-name cinder1 10
```



2. 创建一个 Cinder 卷类型

类型命名为 type1。

```
cinder type-create type1
```



3. 创建一个带 type1 表示的 cinder 卷，大小为 20 GB。

```
cinder create --display-name cinder2 --volume_type type1 20
```



4. 将 cinder1 卷从 10 GB 扩展到 50 GB.

```
cinder extend cinder1 50
```



5. 创建卷快照

```
cinder snapshot-create --display-name snapshot-cinder1 cinder1
```



6. 删除卷

```
cinder delete cinder1
cinder delete cinder2
```



7. 删除 type

```
[root@controller ~]# cinder type-list 
+--------------------------------------+-------+-------------+-----------+
|                  ID                  |  Name | Description | Is_Public |
+--------------------------------------+-------+-------------+-----------+
| 70b779a3-72c2-4ff5-b48c-3fe0aeca46c4 | type1 |      -      |    True   |
+--------------------------------------+-------+-------------+-----------+

[root@controller ~]# cinder type-delete 70b779a3-72c2-4ff5-b48c-3fe0aeca46c4
```