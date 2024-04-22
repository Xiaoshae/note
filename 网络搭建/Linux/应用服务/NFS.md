## NFS服务器的部署

> NFS实现文件共享
>
> rpc服务
>
> 由于NFS服务重启后，端口号会发生变化，所以需要通过rpc服务记录NFS服务的端口号。
>
> 服务端：开启rpc服务，开启nfs服务，nfs服务将新的端口号记录到rpc服务
>
> 客户端：访问rpc服务，获取nfs服务的端口，通过IP地址和端口号访问nfs服务

#### 实验环境：

Sever—nfs—linux：10.10.10.210/24

Client—nfs-linux：10.10.10.220/24

在sever-nfs中搭建nfs服务端共享文件，使用linux客户端连接访问到共享的文件

#### 实验步骤：

#### 1、系统环境基本检查

（IP地址、内存、CPU、发行版、内核版）（确保主机之前可以通讯）

```
[root@master ~]# ip addr  #查看网卡IP
[root@master ~]# df -h    #查看硬盘使用情况
[root@master ~]# free -m  #查看内存使用情况
[root@master ~]# cat /etc/redhat-release  #查看发行版版本号
[root@master ~]# uname -a #查看内核版本号
```

#### 2、在服务端安装nfs和rpcbind服务

需要安装两个服务：nfs-utils、rpcbind

`yum -y install nfs-utils rpcbind   #安装nfs-utils和rpcbind服务`

查看是否安装成功

`rpm -p nfs-utils rpcbind    #查看nfs-utils和rpcbind的版本号`

#### 3、启动rpc服务和nfs服务

```
systemctl start rpcbind        #启动rpc服务
systemctl enable rpcbind    #将rpc服务添加到开机自启
systemctl start nfs            #启动nfs服务
systemctl enable nfs        #将nfs服务添加到开机自启
```

检查服务是否启动成功

`systemctl status nfs         #查看nfs服务状态`

查看rpc中数据库保存的端口号

`rpcinfo -p localhost        #查看本机rpc服务数据库中注册的端口号`

注：111端口号是rpc`服务`的端口，localhost表示本机IP地址

故障案例：无法连接rpc服务

1.目标主机的rpc服务处于停止状态

2.IP、防火墙、selinux配置问题

#### 4）在nfs发布共享目录

配置文件：/etc/exports        #默认无此配置文件，即使有也是空文件，需要自行创建

配置文件格式：

[共享目录路径] [客户端A IP地址]（参数1,参数2) [客户端B IP地址] ...

#### 5）重启服务

目的：通知系统重读配置文件

systemctl restart 服务  ——  （工作中）一般不建议使用此命令

重启服务，执行命令，会立刻关闭服务，然后在启动服务

systemctl reload 服务   —— （工作中）建议使用此命令

重载服务，执行命令，让进程重新读取配置文件，在所有客户端访问结束的时候，才会应用

**查看服务端所共享的目录**

命令：showmount

格式：showmount -e “NFS<mark>服务</mark>器IP”

查看所共享的目录

命令：exportfs -rv

查看所共享的目录**并重启nfs服务**

#### 6）在客户端安装rpcbind和nfs-utils

安装后，启动服务，并添加到开机自启

#### 7)  检测是否可以访问NFS服务端

`rpcinfo -p "[服务端IP地址]"　　　＃rpcinfo -p "10.10.10.210"`

查看所共享的目录

`showmount -e "[服务端IP地址]"        #showmount -t "10.10.10.210"`

#### 8)客户端使用服务端所共享的目录

使用mount挂载

格式：mount -t nfs [服务端IP地址]:[共享绝对路径]（空格）[本地挂载点]

mount -t nfs 10.10.10.210:/opt/nfs /mnt/nfs

注意：需要自行创建本地挂载点目录

#### 9)NFS相关文件

/etc/exports

nfs服务端的配置文件，这个文件中定义了要共享的目录

每行是一个要共享的目录

格式

共享路径  目标(权限属性选项1,选项,选项)

/usr/sbin/exportfs

是一个可执行程序

读取、加载nfs的配置文件，效果等同于执行 systemctl reload nfs

格式：exportfs -rv

/usr/sbin/showmount

是一个可执行程序

远程查看你主机所共享的目录

格式：showmount -e [IP]

/var/lib/nfs/etab

这个文件中记录共享目录的完整参数

这个文件是自动生成

这个文件的内容来源有两部分   主配置文件中的设定 系统的默认设定

/var/lib/nfs/rmtab

显示当前哪些客户端挂载NFS

该文件从centos6开始，就废弃了，可能不存在了