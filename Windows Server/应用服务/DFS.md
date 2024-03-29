# Windows server DFS 命名空间服务配置

## 命名空间

>   命名空间：相当于一个根文件夹，在里面可以创建很多子文件夹，子文件夹中可以在创建子文件夹，也可以创建文件夹目标。
>
>   （子）文件夹：主要是配置整个命名空间（从根文件夹）开始的文件夹目录树，方便用户查找文件夹
>
>   文件夹目标：该文件夹指向一个共享文件夹，打开该文件夹后会显示存储的文件。

注意：

1.   在命名空间中（根文件夹）中只能创建子文件夹，不能创建文件夹目标。
2.   在创建的子文件夹中，可以在创建子文件，或者创建文件夹目标。
3.   但是如果在子文件夹中在创建子文件夹，就不能创建文件夹目标.
4.   如果在子文件夹中创建目标文件夹，就不能创建子文件夹。

​		在一个子文件夹中添加了多个文件夹目标，那么该子文件夹只会显示第一个添加的文件夹目标，其他的文件夹目标中的文件不会显示。在一个子文件夹中创建了多个文件夹目标，一般会配合复制一起使用。



## DFS复制

​		DFS 复制：复制（同步）不同服务器中不同文件夹。例如：添加了Win1和win2服务器中的两个文件夹，在win1上的文件夹添加或删除文件，会同步到win2文件夹，在win2文件夹上操作，也会同步到win1文件夹。

注意：DFS复制只能用于不同服务器中的文件夹复制，不能用于同一计算机不同文件夹之间的复制。

 

复制组成员：添加要进行几台要进行文件夹复制的服务器。

主要成员：在多台服务器中设置一台主要的服务器。

要复制的文件夹：设置主要成员服务器中要复制的文件夹

其他成员上的本地路径：设置其他非主要成员服务器中的文件夹。如果设置为只读（则该文件夹不可删除新建文件，只能读取）



>   注意：配置成功后，其他非主要成员服务器设置的文件夹中的内容将会被全部自动删除，且不会有确认和提示信息，然后将主要成员服务器文件夹中的内容全部复制到非主要成员服务器中的文件夹。
>
>   也就是说：会删除其他成员上的本地路径设置的文件夹中的所有内容，然后将要复制的文件夹设置的文件夹中所有内容复制到其他成员上的本地路径设置的文件夹中。然后接下来**按照DFS复制进行复制** 。

 

# 设置DFS静态端口

dfsrdiag staticrpc /port:xxxx



# 限制所有服务的rpc端口 

netsh int ipv4 set dynamicport tcp start=xxx num=xxx

netsh int ipv4 set dynamicport udp start=xxx num=xxx

（start是起始端口，num是从起始端口开放端口数）