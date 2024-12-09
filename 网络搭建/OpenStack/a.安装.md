# 安装 OpenStack

## Xiandian

系统版本：CentO S 7.2

Xiandian版本：2.2



### 安全配置

关闭防火墙：

```
systemctl stop    firewalld
systemctl disable firewalld
```

关闭selinux（临时）：`setenforce 0`

关闭selinux（永久 /etc/selinux/config ）：`SELINUX=permissive`



### 网络配置

controller节点：

网卡1：192.168.100.100

网卡2：192.168.200.100

compute节点：
网卡1：192.168.100.200

网卡2：192.168.200.200



### 修改主机名

controller节点：`hostnamectl set-hostname controller`

compute 节点：`hostnamectl set-hostname compute`



域名解析配置（修改 /etc/hosts）：

```
192.168.100.100 controller
192.168.100.200 compute
```



### 配置 Yum 源

查看 centos7.2 和 xiandian 2.2 的 uuid

```bash
root@xiaoshae:/# blkid /dev/sr1
/dev/sr1: BLOCK_SIZE="2048" UUID="2017-11-06-10-54-04-00" LABEL="CDROM" TYPE="iso9660"
root@xiaoshae:/# blkid /dev/sr2
/dev/sr2: BLOCK_SIZE="2048" UUID="2015-12-09-22-36-30-00" LABEL="CentOS 7 x86_64" TYPE="iso9660" PTUUID="0930dde7" PTTYPE="dos"
```



修改 /etc/fstab 自动挂载：

```
UUID=2017-11-06-10-54-04-00	/mnt/cdrom/xiandian2.2	iso9660	nofail	0	0
UUID=2015-12-09-22-36-30-00	/mnt/cdrom/centos7.2	iso9660	nofail	0	0
```



修改 Yum 文件：

```
[c7-media]
name=CentOS7
baseurl=file:///mnt/cdrom/centos7.2
gpgcheck=0
enabled=1

[Xiandian-iaas]
name=Xiandian-iaas
baseurl=ftp:///mnt/cdrom/xiandian2.2/iaas-repo
gpgcheck=0
enabled=1
```



### 磁盘管理

添加一块 100 GB 磁盘，使用fdisk创建两个分区

```bash
[root@controller ~]# fdisk /dev/sdb 
WARNING: fdisk GPT support is currently new, and therefore in an experimental phase. Use at your own discretion.
欢迎使用 fdisk (util-linux 2.23.2)。

更改将停留在内存中，直到您决定将更改写入磁盘。
使用写入命令前请三思。

命令(输入 m 获取帮助)：g # 转为 GPT 格式
Building a new GPT disklabel (GUID: A61E8BB4-1CBF-4100-9117-002BE2EA78D5)

命令(输入 m 获取帮助)：n # 创建分区1
分区号 (1-128，默认 1)：
第一个扇区 (2048-419430366，默认 2048)：
Last sector, +sectors or +size{K,M,G,T,P} (2048-419430366，默认 419430366)：+50G #50GB大小
已创建分区 1

命令(输入 m 获取帮助)：n   # 创建分区2
分区号 (2-128，默认 2)：
第一个扇区 (104859648-419430366，默认 104859648)：
Last sector, +sectors or +size{K,M,G,T,P} (104859648-419430366，默认 419430366)： #剩余所有大小
已创建分区 2

命令(输入 m 获取帮助)：w #保存退出
The partition table has been altered!

Calling ioctl() to re-read partition table.
正在同步磁盘。
```



格式化磁盘

```
mkfs.ext4 /dev/sdb1
mkfs.ext4 /dev/sdb2
```



### 正式安装

#### 控制节点

1. 安装 iaas-xiandian 安装包

```
yum install -y iaas-xiandian
```



编辑 /etc/xiandian/openrc.sh （配置环境变量）

```
##--------------------system Config--------------------##
##Controller Server Manager IP. example:x.x.x.x
HOST_IP=192.168.100.10

##Controller Server hostname. example:controller
HOST_NAME=controller

##Compute Node Manager IP. example:x.x.x.x
HOST_IP_NODE=192.168.100.20

##Compute Node hostname. example:compute
HOST_NAME_NODE=compute

##--------------------Rabbit Config ------------------##
##user for rabbit. example:openstack
RABBIT_USER=openstack

##Password for rabbit user .example:000000
RABBIT_PASS=root

##--------------------MySQL Config---------------------##
##Password for MySQL root user . exmaple:000000
DB_PASS=root

##--------------------Keystone Config------------------##
##Password for Keystore admin user. exmaple:000000
DOMAIN_NAME=demo
ADMIN_PASS=root
DEMO_PASS=root

##Password for Mysql keystore user. exmaple:000000
KEYSTONE_DBPASS=root

##--------------------Glance Config--------------------##
##Password for Mysql glance user. exmaple:000000
GLANCE_DBPASS=root

##Password for Keystore glance user. exmaple:000000
GLANCE_PASS=root

##--------------------Nova Config----------------------##
##Password for Mysql nova user. exmaple:000000
NOVA_DBPASS=root

##Password for Keystore nova user. exmaple:000000
NOVA_PASS=root

##--------------------Neturon Config-------------------##
##Password for Mysql neutron user. exmaple:000000
NEUTRON_DBPASS=root

##Password for Keystore neutron user. exmaple:000000
NEUTRON_PASS=root

##metadata secret for neutron. exmaple:000000
METADATA_SECRET=root

##External Network Interface. example:eth1
#INTERFACE_NAME=eno50332200
#INTERFACE_NAME=<网卡2名称>

##First Vlan ID in VLAN RANGE for VLAN Network. exmaple:101
#minvlan=

##Last Vlan ID in VLAN RANGE for VLAN Network. example:200
#maxvlan=

##--------------------Cinder Config--------------------##
##Password for Mysql cinder user. exmaple:000000
CINDER_DBPASS=root

##Password for Keystore cinder user. exmaple:000000
CINDER_PASS=root

##Cinder Block Disk. example:md126p3
##OpenStack Cinder服务中的块存储卷
#BLOCK_DISK=sdb1
#BLOCK_DISK=<磁盘分区1>

##--------------------Trove Config--------------------##
##Password for Mysql Trove User. exmaple:000000
#TROVE_DBPASS=

##Password for Keystore Trove User. exmaple:000000
#TROVE_PASS=

##--------------------Swift Config---------------------##
##Password for Keystore swift user. exmaple:000000
SWIFT_PASS=root

##The NODE Object Disk for Swift. example:md126p4.
##OpenStack Swift对象存储服务的配置。
#OBJECT_DISK=sdb2
#OBJECT_DISK=<磁盘分区2>

##The NODE IP for Swift Storage Network. example:x.x.x.x.
STORAGE_LOCAL_NET_IP=127.0.0.1

##--------------------Heat Config----------------------##
##Password for Mysql heat user. exmaple:000000
HEAT_DBPASS=root

##Password for Keystore heat user. exmaple:000000
HEAT_PASS=root

##--------------------Ceilometer Config----------------##
##Password for Mysql ceilometer user. exmaple:000000
CEILOMETER_DBPASS=root

##Password for Keystore ceilometer user. exmaple:000000
CEILOMETER_PASS=root

##--------------------AODH Config----------------##
##Password for Mysql AODH user. exmaple:000000
AODH_DBPASS=root

##Password for Keystore AODH user. exmaple:000000
AODH_PASS=root
```



2. 安装 iaas-pre-host.sh

```
iaas-pre-host.sh
```

> 注意：**重启系统**或**重新进入bash**
>
> 注意：重启可能会卡住，需要断电关机



3. 安装数据库及消息队列

```
iaas-install-mysql.sh
```



4. 安装认证服务

```
iaas-install-keystone.sh
```



5. 安装 glance 镜像服务

```
iaas-install-glance.sh
```



6. 安装 nova 计算服务

```
iaas-install-nova-controller.sh
```



7. 安装 neutron 网络服务

```
iaas-install-neutron-controller.sh
```



8. 安装 gre 网络服务

```
iaas-install-neutron-controller-gre.sh
```



9. 安装 Bashboard 服务

```
iaas-install-dashboard.sh
```



#### 计算节点

1. 安装 iaas-xiandian 安装包

```
yum install -y iaas-xiandian
```

编辑 /etc/xiandian/openrc.sh （配置环境变量）

注：按照控制节点的模板进行配置，注意修改 网卡2 的名称



2. 安装 iaas-pre-host.sh

```
iaas-pre-host.sh
```

> 注意：**重启系统**或**重新进入bash**
>
> 注意：重启可能会卡住，需要断电关机



3. 安装 nova 计算服务

```
iaas-install-nova-compute.sh
```



4. 安装 neutron 网络服务

```
iaas-install-neutron-compute.sh
```



5. 安装 gre 网络服务

```
iaas-install-neutron-compute-gre.sh
```

