# FTP 文件传输协议

文件传输协议（FTP）是目前互联网上最古老且使用最广泛的协议之一。

其目的是在不需要用户直接登录到远程主机或了解如何使用远程系统的情况下，在网络上的计算机主机之间可靠地传输文件。

它允许用户使用一组标准的简单命令访问远程系统上的文件。



FTP 需要多个网络端口才能正常工作，当 FTP 客户端应用程序发起与 FTP 服务器的连接时，它会使用TCP连接服务器上的 **21** 端口，即**命令端口**，此端口用于向服务器发出所有命令。

从服务器请求的任何数据都通过数据端口返回给客户端，**数据**连接的**端口号**以及数据连接的初始化方式**取决于客户端是**以**主动模式**还是**被动模式**请求数据。



主动模式：主动模式的数据传输由 FTP 客户端发起时，服务器会从服务器上的 20 端口连接到客户端指定的 IP 地址和一个随机的非特权端口（大于 1024）。

注意：因为客户端防火墙常常拒绝来自主动模式FTP服务器的连接，所以出现**被动模式FTP**。



被动模式：被动模式像主动模式一样，由 FTP 客户端应用程序发起。在请求服务器上的数据时，FTP 客户端指示它希望以被动模式访问数据，服务器提供服务器上的 IP 地址和一个随机的非特权端口（大于 1024）。然后，客户端连接到该端口以下载请求的信息。

注意：限制被动模式FTP连接的非特权端口范围，可以简化服务器防火墙规则的管理。



参考链接：

1. [【红帽 FTP 】](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/s1-ftp)

2. [【vsftpd 官方手册】](http://vsftpd.beasts.org/vsftpd_conf.html)
3. [【 vsftpd 配置选项】](http://ftp.pasteur.fr/mirrors/centos-vault/3.6/docs/html/rhel-rg-en-3/s1-ftp-vsftpd-conf.html)

## vsftpd

vsftpd  一个快速、稳定和安全的 FTP 守护进程。



**与 vsftpd 一起安装的文件**

**vsftpd** RPM 会将守护进程 **/usr/sbin/vsftpd** 其配置文件及相关文件和 FTP 目录安装到系统中。



下是在配置 vsftpd 时最常考虑的文件和目录列表：

- **/etc/pam.d/vsftpd** 是 vsftpd 的可插拔认证模块 PAM 配置文件。此文件定义了用户登录到 FTP 服务器必须满足的要求。
- **/etc/vsftpd/vsftpd.conf** 是 vsftpd 的配置文件。
- **/etc/vsftpd.ftpusers** 是不允许登录 vsftpd 的用户列表。
- **/etc/vsftpd.user_list **此文件可以根据 **userlist_deny** 指令在 **/etc/vsftpd/vsftpd.conf** 中设置为 YES （默认）或 NO ，以拒绝或允许列出的用户访问。如果使用 **/etc/vsftpd.user_list** 授予用户访问权限，则列出的用户名不得出现在 **/etc/vsftpd.ftpusers** 中。
- **/var/ftp/** 是由 vsftpd 提供的文件所在的目录。它还包含匿名用户的 /var/ftp/pub/ 目录 这两个目录都是世界可读的，但只有 root 用户可以写入。



**配置文件**

所有 **vsftpd** 的配置都由其配置文件 **/etc/vsftpd/vsftpd.conf** 处理。

每个指令在文件中单独一行，并遵循以下格式：`<directive>=<value>`

**提示：指令中的、等号和之间不得有任何空格。<u>注释</u>必须以井号（ `#` ）开头，守护进程会忽略这些行。**



**文件传输**

**write_enable**：当启用时，允许执行可以更改文件系统的 FTP 命令，例如 DELE（删除文件）、RNFR（重命名起始命令）和 STOR（上传新文件）。默认 **no** 。

**download_enable**：启用后，允许文件下载。默认 **yes**。

**chown_uploads**：启用后，所有匿名用户上传的文件都归 **chown_username** 指令中指定的用户所有。默认 **no**。

**chown_username**：如果启用 **chown_uploads** 指令，指定匿名上传文件的所有权。默认 **root**。



**登录选项**

**anonymous_enable**：启用后，允许匿名用户登录。接受 **anonymous** 和 **ftp** 作为用户名。默认 **no**。

**local_enable**：启用后，允许本地用户登录系统。默认 **yes**。





**匿名用户选项**



以下列出了控制匿名用户访问服务器的指令：

**anon_root**：指定在匿名用户登录后，vsftpd 切换到的目录。

**anon_world_readable_only**：匿名用户只能下载那些被设置为“世界可读”（world-readable）的文件（权限为允许其他用户（other users）或者所有人（world）可以读取的文件）。

**ftp_username**：指定用于匿名FTP用户的本地用户账号（在 /etc/passwd 中列出）。在 /etc/passwd 中为该用户指定的家目录即是匿名FTP用户的根目录。（默认：ftp）

**anon_upload_enable**：与 **write_enable** 指令一起启用时，允许匿名用户在具有写权限的父目录中上传文件。（默认：no）

**anon_mkdir_write_enable**： 与 **write_enable** 指令一起启用时，允许匿名用户在具有写权限的父目录中创建新目录。（默认：no）

**anon_other_write_enable**：如果设置为是，则允许匿名用户执行除上传和创建目录之外的写操作，例如删除和重命名。（默认：no）

**no_anon_password**： 启用后，匿名用户无需输入密码。（默认：no）

**secure_email_list_enable**：当启用此选项时，只接受为匿名登录预设的一系列电子邮件密码。除非所提供的密码列在 **/etc/vsftpd.email_passwords** 文件中，否则将阻止匿名登录。该文件的格式为每行一个密码，并且不允许有尾随的空白字符。

下面是一个示例文件（三个有效的密码，匿名用户可以使用这些密码之一来登录FTP）：

```
examplepassword1
anotherValidPASSWORD2
yetAnotherPaSsw0rd
```



**本地用户**





**chroot_local_user**：启用后，本地用户在登录后将变更根目录到他们的主目录。

**chroot_list_enable**：当启用时，登录时将文件中列出的本地用户放置在 **chroot** 监狱中，该文件在 chroot_list_file 指令中指定。

**chroot_list_file**：指定当 **chroot_list_enable** 指令设置为 **YES** 时引用的包含本地用户列表的文件。

仅启用 **chroot_local_user**：所有用户**被 change root**。

仅启用 **chroot_list_enable**：**chroot_list_file** 中的用户**被 change root**。

都启用 **chroot_local_user** 和 **chroot_list_enable**：**除了 chroot_list_file** 中的用户，其他用户**被change root**。





**local_root**：指定本地用户登录后更改到的目录 `vsftpd` 。

**chmod_enable**：启用时，允许本地用户使用 FTP 命令 **SITE CHMOD** 更改文件权限。

**guest_enable**： 启用后，所有非匿名用户都将以用户 `guest` 的身份登录，该用户是在 `guest_username` 指令中指定的本地用户。

**guest_username**：指定 `guest` 用户映射到的用户名。

**passwd_chroot_enable**：当与 **chroot_local_user** 指令一起启用时，vsftpd 会根据 **/etc/passwd** 文件中用户家目录内**是否出现 /./ 字段**来改变本地用户的根目录。

**user_config_dir**：指定包含本地系统用户名称的配置文件的路径，这些文件包含特定于该用户设置。用户配置文件中的任何指令都会覆盖 **/etc/vsftpd/vsftpd.conf** 中的指令。





# vsftpd服务配置

## 虚拟用户

### vsftpd基础配置

```shell
vsftpd服务以及基础依赖
dnf -y install vsftpd libdb-utils
systemctl start vsftpd && systemctl enable vsftpd
systemctl stop firewalld && systemctl disable firewalld
```

配置文件路径:/etc/vsftpd/

### 创建虚拟用户映射本地用户

`useradd ftpuser -d /home/ftpuser -s /sbin/nologin`

设置家目录为/home/ftpuser 设置该用户不能用于登录Linux

### 创建虚拟用户信息和权限

```shell
[root@linux4 /]# cd /etc/vsftpd/
[root@linux4 vsftpd]# tree
.
├── ftpusers
├── user_list
├── vsftpd.conf
└── vsftpd_conf_migrate.sh

0 directories, 4 files

#创建保存用户和密码的文件夹
[root@linux4 vsftpd]# mkdir passwd
[root@linux4 vsftpd]# cd passwd/
#生成明文账户密码，奇数行账户，偶数行密码
[root@linux4 passwd]# echo -e "ftp1\n123456\nftp2\n123456" > passwd.txt
[root@linux4 passwd]# cat passwd.txt 
ftp1
123456
ftp2
123456

#将明文使用hash进行加密
[root@linux4 passwd]# db_load -T -t hash -f passwd.txt passwd.db

#创建用户权限文件夹
[root@linux4 pam.d]# cd /etc/vsftpd/
[root@linux4 vsftpd]# mkdir user
[root@linux4 vsftpd]# cd user/

#注意：用户权限文件中，如果配置文件中的语法错误，不会影响vsftpd的启动，也就是启动时不会报错
#创建用户权限文件（文件名称和虚拟用户的用户名称一致，passwd.txt中的）
[root@linux4 user]# touch ftp1 ftp2
[root@linux4 user]# echo -e "write_enable=yes
> anon_upload_enable=yes
> anon_mkdir_write_enable=yes
> anon_other_write_enable=yes
> anon_umask=022
> deny_file={*.docx,*.xlsx}
> local_root=/home/ftpuser/ftp1" > ftp1

[root@linux4 user]# cat ftp1
write_enable=yes #允许写入
anon_upload_enable=yes #允许上传
anon_mkdir_write_enable=yes #允许创建
anon_other_write_enable=yes #允许其他权限，例如删除、重命名
anon_umask=022
#7 = 4写入+2读取+1可执行 用7减去设置的。
deny_file={*.docx,*.xlsx} #设置该用户不能上传docx和xlsx的后缀的文件
local_root=/home/ftpuser/ftp1 #设置该虚拟用户家目录

[root@linux4 user]# cat ftp1 > ftp2
[root@linux4 user]# vim ftp2  #该用户只有读取权限
write_enable=no
anon_upload_enable=no
anon_mkdir_write_enable=no
anon_other_write_enable=no
anon_umask=444
local_root=/home/ftpuser/ftp2

[root@linux4 user]# cd ..
[root@linux4 vsftpd]# tree
.
├── ftpusers
├── passwd
│   ├── passwd.db
│   └── passwd.txt
├── user
│   ├── ftp1
│   └── ftp2
├── user_list
├── vsftpd.conf
└── vsftpd_conf_migrate.sh

2 directories, 8 files
[root@linux4 vsftpd]# 
```

### 配置pam.db验证模块

```shell
[root@linux4 vsftpd]# cd /etc/pam.d/
[root@linux4 pam.d]# vim vsftpd-guest 
[root@linux4 pam.d]# cp -p vsftpd vsftpd-guest

#%PAM-1.0
auth       required     pam_userdb.so   db=/etc/vsftpd/passwd/passwd
account    required     pam_userdb.so   db=/etc/vsftpd/passwd/passwd

#此处db指的是生成的passwd.db文件路径（无需文件后缀名）
```

### 配置vsftpd.conf

```shell
anonymous_enable=no
#禁止匿名用户登录

pam_service_name=vsftpd-guest
#刚刚从创建的vsftpd-guest文件

chroot_local_user=yes 
#禁止用户访问除主目录以外的目录

ascii_upload_enable=yes
ascii_download_enable=yes
#设定支持ASCII模式的上传和下载功能

guest_enable=YES 
#启动虚拟用户

guest_username=ftpuser  #之前useradd创建的用户 
#虚拟用户使用的系统用户名

user_config_dir=/etc/vsftpd/user
#虚拟用户使用的配置文件目录
#该目录和该文件也必须由 root 拥有，而不是全局可读。否则将报错500 OOPS: config file not owned by correct user, or not a file
#中文：500 OOPS:配置文件不是正确的用户所有，或者不是文件
#注：不是其中时报错，也不是systemctl status vsftpd查看到的错误，而是centos下使用ftp登陆后显示的错误

allow_writeable_chroot=YES 
#最新版的vsftpd为了安全，如果你将用户限定在只能访问家目录，那么必须设置用户主目录（也就是/home/vsftpd/ftp1）没有写权限，才能登录，或者使用allow_writeable_chroot=YES
```

