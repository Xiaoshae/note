## Samba服务器的部署

> 作用：利用SMB协议实现文件在局域网内的传输

#### 实现环境（确保局域网内各系统能互相通讯）

1.centos8.3（服务端） IP10.10.10.210/24

2.windows7（客户端）IP10.10.10.220/24

#### 实验案例：

john（总经理）

make、cali（市场部）

cale、kado（工厂部）

**管理员：administrator**

共享名                    共享目录                        用户

manger                  /opt/manger                john(rw),administrator(rw)

market                   /opt/market                @market(rw),john(ro),administrator(rw)

factory                   /opt/factory                  @factory(rw),john(ro),administrator(rw)

#### 实验步骤：

##### 1、安装samba服务器

yum -y install samba #使用yum源安装samba服务器

##### 2、启动samba服务器（检查samba服务器是否安装成功）

`systemctl start/status/enable smb   #启动/查看/开启自启smb服务器`

##### 3、创建共享目录

`mkdir /opt/manger /opt/market /opt/factory  #在opt下创建三个目录`

赋予三个目录`777`权限，避免<mark>外部</mark>因素导致smb服务出现问题

在三个目录下使用touch命令，各创建一个文件，文件名和文件夹名称一致

##### 4、创建用户和组

创建6个用户：john、make、cali、cale、kado、administrator

`useradd john  #新建一个用户，名称为john，使用该方法建立剩下用户`

创建2个组：market、factory

`gropadd market #新建一个组，名称为market组，使用该方法建立剩下组`

将用户加入到对应组中

`命令：gpasswd -a 用户名 组名`

`gpasswd -a make market  #将用户make加入到market组`

##### 5、将本地用户转变为`smb`用户

`命令：smbasswd -a [用户名]` 

输入两次密码，没有设置密码直接回车<mark>即可</mark>

`smbpasswd -a john  #将john从本地用户转变为smb用户`

-a 添加用户 -x 删除用户 -d 禁用用户 -e 启用用户 -n 不设置密码

##### 6、编辑smb的主配置文件，实现目录的共享

smb主配置文件路径： /etc/sambe/smb.conf

`vim /etc/sambe/smb.conf`

配置格式

[共享名]

​    comment = [描述] #描述<mark>信息</mark>，可加可不加

​    path = [共享文件夹路径] #*共享文件夹路径，例如/opt/manger

​    valid users = [用户名/组名],[用户名/组名]  #如果是组名前面要加上@符号

​    #例如：john,@market

​    writable = [yes/no]   #写入权限 是/否

​    wite list = [用户名/组名],[用户名/组名]  #（不能写入）除了这里包含的用户/组

​    #人话，没有写入权限，除了wite list里面所包含的用户/组

##### 7、重启samba服务后，用windows7测试

重启samba服务，查看samba服务，确认启动后，使用windows7访问测试

具体命令参考 **步骤2**

打开文件夹，输入\\IP地址\ [回车] 登录<mark>用户</mark>

#### 特殊的共享实现

##### 1、隐藏共享，必须输入指定路径才可看到共享中的文件

实现方法：在格式中新增一条命令

browseble = [yes/<mark>no</mark>]  #yes开启共享，no隐藏共享，默认情况yes，翻译：可浏览

##### 2、基于IP地址的访问控制

允许特定的网段主机访问共享

添加语句 ：hosts allow = [网段] except [IP地址]

hosts allow 10.10.10. except `10.10.10.220`

允许10.10.10.网段下所有IP访问，除了10.10.10.220IP地址主机访问

except后面允许有多个IP地址，IP地址之前使用[空格]进行分隔

##### 3、别名功能

给administrator设置别名为admin

在配置文件，[global]中添加语句

username map = [文件路径]

创建改文件路径和文件，编辑文件，添加语句

[用户名] = [别名],[别名]    #可以添加多个别名，用逗号分隔。

administrator = admin,admin2

4、启用shear级别（开启匿名登录）

在globle添加语句：map to guest = bad user

在[分享文件名]中注释vaild user = [用户]，添加guest ok = yes 或者 public = yes