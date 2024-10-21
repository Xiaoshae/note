# 云平台centos挂载本地yum源

> 目前centos8.3镜像为文本镜像，没有内置相关服务组件，需要通过外部挂载镜像完成yum本地源配置，现基于该问题进行举例说明。

## 1.共享centos8文件

### 1.1在物理机上找到centos.iso镜像文件，并解压/装载。

![image-20211028203353840](images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20211028203353840.png)

### 1.2将解压出来的文件夹/光盘共享

将**DVD驱动器**/**解压出来的文件夹**共享，给予**everyone**读取的权限。

> **记得去更改高级共享里面进行设置，确保开启了文件共享功能。**

![image-20211028204013880](images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20211028204013880.png)

<img src="images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20211028204101144.png" alt="image-20211028204101144" style="zoom:200%;" />

<img src="images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20211028204111544.png" alt="image-20211028204111544" style="zoom:200%;" />

### 1.3使用ping命令确保虚拟机和物理机能够相同

![image-20211028205023770](images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20211028205023770.png)

### 1.4确保能够相同后在虚拟机中进行挂载

<img src="images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20211028204447171.png" alt="image-20211028204447171" style="zoom:200%;" />

> 详细命令说明如下：
>
> mount -t cifs -o username=everyone //物理机ip/共享文件夹名称 /虚拟机文件夹/
>
> PS:如果提示 host is down 则在-o后加vers=2.0,+username=xxx即可

![image-20211028204827826](images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20211028204827826.png)

### 1.5通过修改yum的repo文件即可正常使用yum进行本地安装服务了

![image-20240103122654083](images/%E4%BA%91%E5%B9%B3%E5%8F%B0centos%E6%8C%82%E8%BD%BD%EF%BC%8C%E6%9C%AC%E5%9C%B0yum%E6%BA%90.assets/image-20240103122654083.png)