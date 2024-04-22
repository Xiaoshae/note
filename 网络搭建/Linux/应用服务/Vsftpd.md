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
#最新版的vsftpd为了安全必须用户主目录（也就是/home/vsftpd/ftp1）没有写权限，才能登录，或者使用allow_writeable_chroot=YES
```

