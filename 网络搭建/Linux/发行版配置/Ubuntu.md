# 更新

你可以使用三个命令来升级 Kali：

```
apt upgrade
```

```
apt full-upgrade
```

```
apt dist-upgrade
```

它们之间有细微的差别：

- 该**`apt upgrade`**命令会下载和更新软件包，而不会删除以前安装在 Kali Linux 系统上的任何内容。
- 该**`apt full-upgrade`**命令下载和更新包。但是，如果需要，它还会删除已安装的软件包。
- 该**`apt dist-upgrade`**命令与常规升级相同，同时智能地处理不断变化的依赖项、删除过时的包和添加新的包。



# 设置时区

```
sudo timedatectl set-timezone Asia/Shanghai
```



# 设置系统语言方法

```
sudo apt-get update

sudo apt-get install language-pack-zh-hans

sudo update-locale LANG=zh_CN.UTF-8
```

**注意：需要注销用户重新登录，或者重新启动**



使用xshell等远程连接方式，可以正常显示中文，但是在VMware中会显示菱形乱码，猜测是没有对应的字体给显示。



# hub 2-2

![image-20240510195114769](images/Ubuntu.assets/image-20240510195114769.png)

缺少蓝牙驱动，安装蓝牙后就好了：

```
apt install -y bluetooth
```



python3-pip install on ubuntu 24.04

```
将会同时安装下列软件：
  binutils binutils-common binutils-x86-64-linux-gnu build-essential bzip2 cpp cpp-13 cpp-13-x86-64-linux-gnu cpp-x86-64-linux-gnu
  dpkg-dev fakeroot g++ g++-13 g++-13-x86-64-linux-gnu g++-x86-64-linux-gnu gcc gcc-13 gcc-13-base gcc-13-x86-64-linux-gnu
  gcc-x86-64-linux-gnu javascript-common libalgorithm-diff-perl libalgorithm-diff-xs-perl libalgorithm-merge-perl libasan8
  libatomic1 libbinutils libcc1-0 libctf-nobfd0 libctf0 libdpkg-perl libexpat1-dev libfakeroot libfile-fcntllock-perl libgcc-13-dev
  libgprofng0 libhwasan0 libisl23 libitm1 libjs-jquery libjs-sphinxdoc libjs-underscore liblsan0 libmpc3 libpython3-dev
  libpython3.12-dev libquadmath0 libsframe1 libstdc++-13-dev libtsan2 libubsan1 lto-disabled-list make python3-dev python3-wheel
  python3.12-dev zlib1g-dev
建议安装：
  binutils-doc gprofng-gui bzip2-doc cpp-doc gcc-13-locales cpp-13-doc debian-keyring g++-multilib g++-13-multilib gcc-13-doc
  gcc-multilib autoconf automake libtool flex bison gdb gcc-doc gcc-13-multilib gdb-x86-64-linux-gnu apache2 | lighttpd | httpd bzr
  libstdc++-13-doc make-doc
下列【新】软件包将被安装：
  binutils binutils-common binutils-x86-64-linux-gnu build-essential bzip2 cpp cpp-13 cpp-13-x86-64-linux-gnu cpp-x86-64-linux-gnu
  dpkg-dev fakeroot g++ g++-13 g++-13-x86-64-linux-gnu g++-x86-64-linux-gnu gcc gcc-13 gcc-13-base gcc-13-x86-64-linux-gnu
  gcc-x86-64-linux-gnu javascript-common libalgorithm-diff-perl libalgorithm-diff-xs-perl libalgorithm-merge-perl libasan8
  libatomic1 libbinutils libcc1-0 libctf-nobfd0 libctf0 libdpkg-perl libexpat1-dev libfakeroot libfile-fcntllock-perl libgcc-13-dev
  libgprofng0 libhwasan0 libisl23 libitm1 libjs-jquery libjs-sphinxdoc libjs-underscore liblsan0 libmpc3 libpython3-dev
  libpython3.12-dev libquadmath0 libsframe1 libstdc++-13-dev libtsan2 libubsan1 lto-disabled-list make python3-dev python3-pip
  python3-wheel python3.12-dev zlib1g-dev

```



# 安装`gcc -m32`安装环境

```
apt -y install build-essential
apt -y install lib32readline-dev
```



## Autotools工具

```
apt -y install autoconf automake libtool m4 autoconf-archive
```

```

```



```
autoreconf -i
```



```
root@Xiaoshae:/opt# sudo apt install build-essential lib32readline-dev autoconf automake libtool m4 autoconf-archive
正在读取软件包列表... 完成
正在分析软件包的依赖关系树... 完成
正在读取状态信息... 完成
将会同时安装下列软件：
  autotools-dev bzip2 cpp cpp-11 dpkg-dev fakeroot g++ g++-11 gcc gcc-11 gcc-11-base gcc-11-multilib gcc-multilib
  lib32asan6 lib32atomic1 lib32gcc-11-dev lib32gcc-s1 lib32gomp1 lib32itm1 lib32ncurses-dev lib32ncurses6
  lib32ncursesw6 lib32quadmath0 lib32readline8 lib32stdc++6 lib32tinfo6 lib32ubsan1 libalgorithm-diff-perl
  libalgorithm-diff-xs-perl libalgorithm-merge-perl libasan6 libatomic1 libc-dev-bin libc-devtools libc6-dev
  libc6-dev-i386 libc6-dev-x32 libc6-i386 libc6-x32 libcc1-0 libcrypt-dev libdpkg-perl libfakeroot
  libfile-fcntllock-perl libgcc-11-dev libgd3 libisl23 libitm1 liblsan0 libltdl-dev libmpc3 libncurses-dev libnsl-dev
  libquadmath0 libstdc++-11-dev libtirpc-dev libtsan0 libubsan1 libx32asan6 libx32atomic1 libx32gcc-11-dev
  libx32gcc-s1 libx32gomp1 libx32itm1 libx32quadmath0 libx32stdc++6 libx32ubsan1 linux-libc-dev lto-disabled-list make
  manpages-dev rpcsvc-proto
建议安装：
  gnu-standards autoconf-doc gettext bzip2-doc cpp-doc gcc-11-locales debian-keyring g++-multilib g++-11-multilib
  gcc-11-doc flex bison gdb gcc-doc ncurses-doc glibc-doc bzr libgd-tools libtool-doc libstdc++-11-doc gfortran
  | fortran95-compiler gcj-jdk m4-doc make-doc
下列【新】软件包将被安装：
  autoconf autoconf-archive automake autotools-dev build-essential bzip2 cpp cpp-11 dpkg-dev fakeroot g++ g++-11 gcc
  gcc-11 gcc-11-base gcc-11-multilib gcc-multilib lib32asan6 lib32atomic1 lib32gcc-11-dev lib32gcc-s1 lib32gomp1
  lib32itm1 lib32ncurses-dev lib32ncurses6 lib32ncursesw6 lib32quadmath0 lib32readline-dev lib32readline8 lib32stdc++6
  lib32tinfo6 lib32ubsan1 libalgorithm-diff-perl libalgorithm-diff-xs-perl libalgorithm-merge-perl libasan6 libatomic1
  libc-dev-bin libc-devtools libc6-dev libc6-dev-i386 libc6-dev-x32 libc6-i386 libc6-x32 libcc1-0 libcrypt-dev
  libdpkg-perl libfakeroot libfile-fcntllock-perl libgcc-11-dev libgd3 libisl23 libitm1 liblsan0 libltdl-dev libmpc3
  libncurses-dev libnsl-dev libquadmath0 libstdc++-11-dev libtirpc-dev libtool libtsan0 libubsan1 libx32asan6
  libx32atomic1 libx32gcc-11-dev libx32gcc-s1 libx32gomp1 libx32itm1 libx32quadmath0 libx32stdc++6 libx32ubsan1
  linux-libc-dev lto-disabled-list m4 make manpages-dev rpcsvc-proto
升级了 0 个软件包，新安装了 79 个软件包，要卸载 0 个软件包，有 0 个软件包未被升级。
需要下载 87.2 MB 的归档。
解压缩后会消耗 303 MB 的额外空间。
您希望继续执行吗？ [Y/n]
```



## 编译安装

```
sudo apt-get install libgmp-dev libmpfr-dev libmpc-dev
../configure --prefix=/root/envir/gcc-13.2.0
make -j16
make install
```



# 如何在 Ubuntu 上隐藏 SSH 欢迎消息

通过 SSH 登录访问远程 Ubuntu 服务器时，您会看到以下 SSH 欢迎屏幕：

![image-20241002110651017](./images/Ubuntu.assets/image-20241002110651017.png)

用户在连接到运行 Ubuntu 或任何基于 Debian 的发行版的服务器时通常会遇到此屏幕。

最初拥有它很好，但是每次服务器连接处理冗长的 SSH 欢迎文本最终会变得很麻烦。



SSH 欢迎消息显示在位于`/etc/update-motd.d/`路径的文件和`/etc/ssh/sshd_config`文件中定义的设置中。

要禁止显示欢迎消息，请首先打开终端并使用您喜欢的文本编辑器修改**/etc/ssh/sshd_config**文件。

文件打开后，找到`PrintMotd`字段并将其值设置为`no` 。

![image-20241002110743421](./images/Ubuntu.assets/image-20241002110743421.png)



保存并关闭文件，然后继续编辑/etc/pam.d/sshd文件。

然后找到下面两行，找到它们后，通过在每行前面放置#来注释它们，如下所示：

```
# session    optional     pam_motd.so  motd=/run/motd.dynamic
# session    optional     pam_motd.so noupdate
```

注意：如果想终端登录也没有欢迎消息，对 /etc/pam.d/login 文件的这一部分内容进行相同的操作



以下是对上述两行进行注释后的文件外观：

![image-20241002110823770](./images/Ubuntu.assets/image-20241002110823770.png)

保存并关闭文件，通过运行以下命令重新启动 SSH 服务器：

```
sudo systemctl restart ssh
```



完成任务后，尝试连接到远程服务器，您会发现这次您不会收到欢迎消息，如下所示：

![image-20241002110855305](./images/Ubuntu.assets/image-20241002110855305.png)



参考链接：

1. [如何在 Ubuntu 上隐藏 SSH 欢迎消息 | How to Hide the SSH Welcome Message on Ubuntu | HackerNoon](https://hackernoon.com/how-to-hide-the-ssh-welcome-message-on-ubuntu)





# 常见错误



# 配置软件源

```
/etc/apt/sources.list


deb https://mirrors.aliyun.com/kali kali-rolling main non-free contrib
deb-src https://mirrors.aliyun.com/kali kali-rolling main non-free contrib

#See https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/
#deb http://http.kali.org/kali kali-rolling main contrib non-free

# Additional line for source packages
# deb-src http://http.kali.org/kali kali-rolling main contrib non-free
```



# 签名失效

```shell
wget archive.kali.org/archive-key.asc   #下载签名
apt-key add archive-key.asc   #安装签名
```



# 配置环境变量

```shell
export PATH="$PATH:/you/path"
source /etc/profile
```

注意：

- 一定要加引号
- 如果source有问题，可以通过重启解决





# Ubuntu Desktop允许root用户登录



## 1. 设置root密码

```
sudo passwd root
```

```
sudo -i
passwd root
```



## 2. 编辑GDM文件

修改`	`文件，添加`AllowRoot=true`，更改后保存推出文件。

```
AllowRoot=true
```

![编辑 GDM 配置文件以允许 root 登录](images/Ubuntu.assets/01-how-to-allow-gui-root-login-on-ubuntu-22-04-jammy-jellyfish-linux.png)



## 3. PAM 身份验证守护进程配置文件

`/etc/pam.d/gdm-password`文件，注释一行`auth   required        pam_succeed_if.so user != root quiet_success`

![拒绝 root 访问图形用户界面的注释行](images/Ubuntu.assets/02-how-to-allow-gui-root-login-on-ubuntu-22-04-jammy-jellyfish-linux.png)



## 4. 重启系统



## 安装ssh服务

```
apt-get install -y openssh-server
```



## SSH登录缓慢



### 1. DNS反向解析

SSH会进行反向DNS查找以解析连接主机，这可能导致延迟。

可以在服务器的sshd_config文件中设置`UseDNS no`来禁用反向查找



### 2. 空密码登录

不知道为什么，如果开启了空密码登录，会导致SSH连接时2-3秒的延迟。

`PermitEmptyPasswords yes`：这个选项表示是否允许空密码登录。如果设置为 yes，则允许用户使用空密码进行 SSH 登录。如果设置为 no，则不允许空密码登录。（**默认为：no**）



### 3.GSSAPI认证	

GSSAPI认证需要对服务器端的IP地址进行反解析，如果服务器的IP地址没有配置PTR记录，那么就会在这里卡住。

sshd_config文件中将`GSSAPIAuthentication yes`更改为`no`



# 安装Vmware-tools

```
sudo apt-get install open-vm-tools-desktop
```





# 安装deb软件包

```
dpkg -i ***.deb
```



# Chrome 	安装后无法启动

## 1. 查看浏览器位置

```
whereis google-chrome  
google-chrome: /usr/bin/google-chrome /usr/share/man/man1/google-chrome.1.gz  
```



## 2. 修改浏览器

```
vim /usr/bin/google-chrome

exec -a "$0" "$HERE/chrome" "$@"
#修改为
exec -a "$0" "$HERE/chrome" "$@" --user-data-dir --no-sandbox 
```



# Which service should be restarted ?

![在此处输入图像描述](images/Ubuntu.assets/lAFlE.png)

编辑 /etc/needrestart/needrestart.conf 文件

```
vim /etc/needrestart/needrestart.conf
#$nrconf{restart} = 'i';#修改为
$nrconf{restart} = 'a';
```



# netplan网络配置

```
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      ## 可以ip a查看以太网连接名称
      dhcp4: true
    enp0s8:
      # addresses: []
      ## addresses添加网络掩码，如192.168.56.3/24
      addresses: [192.168.5.3/24]
      # gateway4: 10.10.10.1
      ## gateway4已经废弃，推荐使用routes
      routes:
      - to: "default"
        via: "192.168.5.1"
      nameservers:
        search: [mydomain , otherdomain ]
        addresses: [192.168.5.1 , 114.114.114.114]
      optional: true
```

```
netplan apply
```



# NetworkManager网络配置



## 1. 安装NetworkManager

```
 apt install network-manager
 systemctl enable NetworkManager
 systemctl start NetworkManager
```



## 2. 配置使用NetworkManager



修改配置文件 /etc/NetworkManager/NetworkManager.conf

```
vim /etc/NetworkManager/NetworkManager.conf 
```

![img](images/Ubuntu.assets/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBAd2VpeGluXzUyMzQyMTUz,size_20,color_FFFFFF,t_70,g_se,x_16.png)



修改配置文件/etc/netplan/00-installer-config.yaml

```
vim /etc/netplan/00-installer-config.yaml
```

```
network:
  version: 2
  renderer: NetworkManager
```

![image-20240201104826927](images/Ubuntu.assets/image-20240201104826927.png)



```
netplan apply
```



## 3. systemd-networkd冲突

如果您正在使用 `NetworkManager` 来管理网络，那么您通常不需要 `systemd-networkd` 或 `systemd-networkd-wait-online.service`。

同时开启了这两个来管理网络，可以会导致冲突，有一个在开启时无法正常工作，导致开机等待时机变长。

已经使用 `NetworkManager` ，那么您可以考虑禁用 `systemd-networkd-wait-online.service` 服务。您可以使用以下命令来停止并禁用该服务：

```bash
sudo systemctl stop systemd-networkd-wait-online.service
sudo systemctl disable systemd-networkd-wait-online.service
```





# Ubuntu LVM 磁盘扩容

## 1. 环境介绍

```
# sda
设备          大小 类型
/dev/sda1    1M BIOS 启动
/dev/sda2  1.8G Linux 文件系统
/dev/sda3  8.2G Linux 文件系统 #挂在到根路径
```



## 2. 扩充整个磁盘

VMDX将磁盘从20GB扩容到100GB



## 3. 扩容sda3分区

不删除原有分区的数据，而是直接在原有的分区扩充空间，使用 parted 或者 gparted 工具。

```
 apt-get install gparted
```

```
 gparted
```

在 gparted 的界面中，选择你想要调整大小的分区，然后选择"调整大小/移动"，注意：对齐选择Mib



## 4. 扩容物理卷（PV）

首先，你需要使用pvresize命令来扩容物理卷。这个命令会调整物理卷的大小以使用新的磁盘空间

```
    sudo pvresize /dev/sda3
```



## 5. 扩容逻辑卷（LV）：

使用lvextend命令来扩容逻辑卷。

```
sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
```



## 6. 扩大文件系统

扩展逻辑卷后，你需要调整文件系统的大小以使用新的逻辑卷空间。对于基于ext3和ext4的文件系统，你可以使用resize2fs命令。

```
sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
```



# update-alternatives多版本管理

通过update-alternatives工具来进行，多版本管理

```
update-alternatives --install [软链接路径] [软件标识名] [可执行文件路径] [优先级]
```



添加第一个版本

```
update-alternatives --install /usr/local/sbin/checksec checksec /root/envir/checksec.sh-2.6.0/checksec 2
```



添加第二个版本

```
update-alternatives --install /usr/local/sbin/checksec checksec /usr/local/bin/checksec 1
```



查看checksec版本的配置，*表示当前在使用哪个版本，使用此命令可以指定一个版本。

auto mode 表示自动模式，按照优先级来使用版本

manual mode 表示手动模式，使用指定的版本

![image-20240201201818703](images/Ubuntu.assets/image-20240201201818703.png)



## 删除一个版本

```
sudo update-alternatives --remove [版本标识符] [路径]
```

```
sudo update-alternatives --remove checksec /root/envir/checksec.sh-2.6.0/checksec
```



# 解决过时的密钥





# AppImage环境

```
sudo apt install -y fuse libfuse2
sudo apt install -y gnome-terminal
sudo apt install -y qtcreator qtbase5-dev qt5-qmake cmake

```





# 安装中文编码和字体

```
sudo apt-get install language-pack-zh-han*
sudo apt install $(check-language-support)
sudo apt install ttf-wqy-microhei ttf-wqy-zenhei xfonts-intl-chinese

```



# ubuntu 22.04 安装 ntfs exFat

```
sudo apt install ntfs-3g
```

```
sudo apt install exfat-fuse exfatprogs
```

