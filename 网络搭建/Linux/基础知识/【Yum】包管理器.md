# Yum包管理器

yum（ Yellow dog Updater, Modified）是一个在 Fedora 和 RedHat 以及 SUSE 中的 Shell 前端软件包管理器。

基于 RPM 包管理，能够从指定的服务器自动下载 RPM 包并且安装，可以自动处理依赖性关系，并且一次安装所有依赖的软件包，无须繁琐地一次次下载、安装。



## 配置Yum仓库

使用Yum前现需要配置Yum仓库，Yum仓库的配置分为好几种：本地（离线）Yum仓库，网络Yum仓库。



Yum仓库配置文件夹位置：`/etc/yum.repos.d/`

Yum仓库配置文件扩展名：`***.repo`

Yum管理器会自动加载`/etc/yum.repos.d/`文件夹中，以`repo`扩展名结尾的文本文件。



CentOS8中的`/etc/yum.repos.d/`文件夹中默认存在以下配置文件：

```
CentOS-Linux-AppStream.repo          CentOS-Linux-Debuginfo.repo    CentOS-Linux-FastTrack.repo
CentOS-Linux-Plus.repo			     CentOS-Linux-BaseOS.repo       CentOS-Linux-Devel.repo
CentOS-Linux-HighAvailability.repo   CentOS-Linux-PowerTools.repo   CentOS-Linux-ContinuousRelease.repo
CentOS-Linux-Extras.repo     		 CentOS-Linux-Media.repo        CentOS-Linux-Sources.repo
```

这些都是CentOS8官方网络Yum仓库源，但是CentOS8官方网络Yum仓库已经停止维护了，默认的仓库已经无法使用了。

现在可以选择删除这些配置文件，或者将他们启动到其他目录进行备份。



### 本地Yum仓库

本地Yum仓库是将所有的软件包存储在本地磁盘上，在Yum配置文件中将仓库位置指向指定的路径。



首先需要将CentOS8中的软件包存储在本地磁盘上，在CentOS8的ISO镜像文件中就存在一些软件包。

将CentOS8中的ISO镜像文件挂载到文件夹中。

1. 将ISO添加到Vmware虚拟机中

![image-20240614091905976](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240614091905976.png)



2. 将Vmware中的ISO挂在到文件夹中

```
[root@localhost mnt]# mount /dev/cdrom /mnt/iso/
mount: /mnt/iso: WARNING: device write-protected, mounted read-only.
```



查看/mnt/iso中的文件

```
[root@localhost iso]# ls
AppStream  BaseOS  EFI  images  isolinux  LICENSE  media.repo  TRANS.TBL
```

这些都是ISO镜像文件中的内容，其中AppStream和BaseOS中存储了很多软件包



现在创建一个新的repo文件，并开始编写本地Yum源配置文件。

```
[root@localhost yum.repos.d]# touch CentOS8.repo
```



配置文件模板：

```
[仓库标识符]
name=仓库描述性名称
baseurl=[协议][文件位置]

gpgcheck=[0/1]
# 是否进行密钥检查	0否	1是
enable=[0/1]
# 是否启用该仓库	0否	1是
```



示例：

```
[AppStream]
name=AppStream
baseurl=file:///mnt/iso/AppStream
gpgcheck=0
enable=1

[BaseOS]
name=BaseOS
baseurl=file:///mnt/iso/BaseOS
gpgcheck=0
enable=1
```

- `[AppStream]` 和 `[BaseOS]`：这些是仓库的标识符。它们用于区分不同的仓库配置。当你使用yum或dnf命令时，你可以通过这些名称引用特定的仓库。
- `name=AppStream - text` 和 `name=BaseOS`：这是仓库的描述性名称，它不会直接影响仓库的功能，但可以帮助用户识别仓库的用途。例如，`AppStream`通常包含额外的应用程序和组件，而`BaseOS`则包含操作系统的核心组件。
- `baseurl=file:///mnt/iso/AppStream` 和 `baseurl=file:///mnt/iso/BaseOS`：这些行指定了仓库的位置。
- `gpgcheck=0`：这表示禁用了对软件包签名的检查。
- `enable=1`：这表明仓库当前是启用状态，即系统可以从此仓库中查找并安装软件包。

baseurl指向仓库文件夹的位置，而[]和name仅仅只是对这个仓库的标识和描述，即使使用其他的名称也不会有影响。



清除元数据缓存

```
[root@localhost /]# dnf clean all 
13 文件已删除
```



建立元数据

```
[root@localhost /]# dnf makecache
AppStream				454 MB/s | 7.5 MB     00:00    
BaseOS					149 MB/s | 2.6 MB     00:00    
元数据缓存已建立。
```



安装一个软件

![image-20240614093530275](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240614093530275.png)



### 网络Yum仓库

网络Yum仓库首先要求计算机可以访问互联网，然后在baseurl中使用http、ftp等文件传输协议下载非本机的Yum仓库中的软件包。

国内的CentOS8仓库，可以使用阿里云的镜像站。

网址：https://developer.aliyun.com/mirror/centos?spm=a2c6h.13651102.0.0.4c2d1b11XQVN40



**注意：首先需要配置网络，并且可以ping mirrors.aliyun.com**

![image-20240614094945920](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240614094945920.png)



阿里云镜像站提供了命令，可以一键将repo配置文件下载到本地。

```
curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-vault-8.5.2111.repo
```

![image-20240614095017040](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240614095017040.png)



清除元数据缓存

```
[root@localhost /]# dnf clean all 
13 文件已删除
```



建立元数据

![image-20240614095211619](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240614095211619.png)



安装一个软件

![image-20240614095257385](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240614095257385.png)



# 远程Yum源

所谓远程Yum源指的是在Windows上打开一个镜像，然后使用Windows的SMB协议共享该镜像所在的盘符，然后在Linux上将其挂载到目录中。

高级共享设置：

1. 控制面板
2. 网络和Internet
3. 网络和共享中心
4. 高级共享设置

![image-20240621190132531](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240621190132531.png)

专用：

- 启用网络发现（启用网络连接设备的自动设置）
- 启用文件和打印机共享

来宾或公用：

- 启用网络发现
- 启用文件和打印机共享

所有网络：

- 启用共享以便可以访问网络的用户可以读取和写入公用文件夹中的文件
- 无密码保护的共享



注意：如果是使用`guest`或`everyone`用户进行共享时，必须选择**无密码保护的共享**，否则在挂载时可能报错**无法以只读方式挂载**



共享驱动器盘符：

![image-20240621190535568](./images/%E3%80%90Yum%E3%80%91%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8.assets/image-20240621190535568.png)



在Linux上创建文件夹，并将盘符挂在到文件夹上：

```bash
[root@linux1 mnt]# mount -t cifs -o vers=2.0,username=everyone //10.12.0.1/G /mnt/iso/
[root@linux1 mnt]# cd iso/
[root@linux1 iso]# pwd
/mnt/iso
[root@linux1 iso]# ls
AppStream  BaseOS  EFI  images  isolinux  LICENSE  media.repo  TRANS.TBL
```



配置Yum源的路径为`/mnt/iso/`：

```bash
[root@linux1 yum.repos.d]# pwd
/etc/yum.repos.d
[root@linux1 yum.repos.d]# cat Centos8.repo 
# CentOS-Linux-Media.repo
#
# You can use this repo to install items directly off the installation media.
# Verify your mount point matches one of the below file:// paths.

[media-baseos]
name=CentOS Linux  - Media - BaseOS
baseurl=file:///mnt/iso/BaseOS
gpgcheck=0
enabled=1

[media-appstream]
name=CentOS Linux  - Media - AppStream
baseurl=file:///mnt/iso/AppStream
gpgcheck=0
enabled=1
[root@linux1 yum.repos.d]# dnf makecache
CentOS Linux  - Media - BaseOS                                                                                                    44 MB/s | 2.6 MB     00:00    
CentOS Linux  - Media - AppStream                                                                                                 70 MB/s | 7.5 MB     00:00    
元数据缓存已建立。
[root@linux1 yum.repos.d]# 
```

