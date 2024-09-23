

# Volatility2 制作 Profile（CentOS8）



在 CentOS 8 中，您可以按照以下步骤来安装：

您可以使用以下命令来安装1：
sudo yum install kernel-devel

您可以使用以下命令来安装2：
sudo yum install gcc gcc-c++ make



## 环境配置

 linux-headers、build-essential、dwarfdump



安装 linux-headers：在 CentOS 8 中，linux-headers 对应的是 kernel-devel 包。

```
dnf -y install kernel-headers
```



安装 build-essential：在 CentOS 中，build-essential 的等效包括 gcc、gcc-c++ 和 make。

```
dnf -y install gcc gcc-c++ make
#or
dnf -y install "开发工具"
```



## dwarfdump

最开始使用dnf search进行查找，是可以查找到的。

但是安装后，执行dwarfdump命令却显示命令未找到

```
[root@localhost linux]# dnf search dwarf
上次元数据过期检查：1 day, 1:52:42 前，执行于 2023年11月14日 星期二 21时59分18秒。
============================================ 名称 和 概况 匹配：dwarf ============================================
libdwarf.x86_64 : Library to access the DWARF Debugging file format
libdwarf.i686 : Library to access the DWARF Debugging file format

```



**去RHEL找到了这样的一篇文章**

 9.11. Compilers and development tools

**`libdwarf` has been deprecated**

The library has been deprecated in RHEL 8. The library will likely not be supported in future major releases. Instead, use the and libraries for applications that wish to process ELF/DWARF files. `libdwarf``elfutils``libdw`

Alternatives for the program are the program or the program, both used by passing the flag. `libdwarf-tools``dwarfdump``binutils``readelf``elfutils``eu-readelf``--debug-dump`

([BZ#1920624](https://bugzilla.redhat.com/show_bug.cgi?id=1920624))

**The `gdb.i686` packages are deprecated**

In RHEL 8.1, the 32-bit versions of the GNU Debugger (GDB), , were shipped due to a dependency problem in another package. Because RHEL 8 does not support 32-bit hardware, the packages are deprecated since RHEL 8.4. The 64-bit versions of GDB, , are fully capable of debugging 32-bit applications. `gdb.i686``gdb.i686``gdb.x86_64`

If you use , note the following important issues: `gdb.i686`

- The packages will no longer be updated. Users must install instead. `gdb.i686``gdb.x86_64`
- If you have installed, installing will cause to report . This is expected. Either uninstall or pass the option to remove and install . `gdb.i686``gdb.x86_64``dnf``package gdb-8.2-14.el8.x86_64 obsoletes gdb < 8.2-14.el8 provided by gdb-8.2-12.el8.i686``gdb.i686``dnf``--allowerasing``gdb.i686``gdb.x8_64`
- Users will no longer be able to install the packages on 64-bit systems, that is, those with the packages. `gdb.i686``libc.so.6()(64-bit)`

(BZ#1853140)



**翻译为大白话后就是**

在 RHEL 8中，`libdwarf` 和 `dwarfdump` 已经被弃用。取而代之的是 `elfutils` 和 `libdw` 库。

对于 `dwarfdump`，您可以使用 `readelf`（来自 `binutils` 包）或 `eu-readelf`（来自 `elfutils` 包）作为替代，它们都可以通过传递 `--debug-dump` 标志来使用。



注：RHEL 8 基本等价于 CentOS，虽然官方给出了替代方法，但是volatility2可不认这个，所以只能通过编译安装的方式安装dwarfdum



dwarfdum下载网页：https://www.prevanders.net/dwarf.html



编译安装dwarfdum

```
#解压后准备构建目录
[root@localhost soft]# tar -xf libdwarf-0.8.0.tar.xz 
[root@localhost soft]# cd libdwarf-0.8.0/
[root@localhost libdwarf-0.8.0]# mkdir build
[root@localhost libdwarf-0.8.0]# cd build/

#初始化
[root@localhost build]# ../configure 
checking build system type... x86_64-pc-linux-gnu
checking host system type... x86_64-pc-linux-gnu
checking for gcc... gcc
checking whether the C compiler works... yes
checking for C compiler default output file name... a.out
...........

#编译安装
[root@localhost build]# make -j16 && make install
make  all-recursive
make[1]: 进入目录“/opt/soft/libdwarf-0.8.0/build”
Making all in src/lib/libdwarf
make[2]: 进入目录“/opt/soft/libdwarf-0.8.0/build/src/lib/libdwarf”
  CC       libdwarf_la-dwarf_abbrev.lo
  CC       libdwarf_la-dwarf_alloc.lo
  CC       libdwarf_la-dwarf_arange.lo
  CC       libdwarf_la-dwarf_crc.lo
  CC       libdwarf_la-dwarf_crc32.lo
........

#看看是否成功， 成功了
[root@localhost build]# which dwarfdump 
/usr/local/bin/dwarfdump

[root@localhost build]# dwarfdump 
No object file name provided to dwarfdump
To see the options list: dwarfdump -h
```



## 开始编译

从github中git clone volatility (2)

https://github.com/volatilityfoundation/volatility

进入volatility目录，然后进入tools/linux目录，不同版本的路径可能不一样

我的版本是2.6.1

```
[root@localhost tools]# cd volatility
[root@localhost volatility]# ls
AUTHORS.txt    CREDITS.txt  Makefile     pyinstaller       resources  volatility
CHANGELOG.txt  LEGAL.txt    MANIFEST.in  pyinstaller.spec  setup.py   vol.py
contrib        LICENSE.txt  PKG-INFO     README.txt        tools
[root@localhost volatility]# cd tools/linux/
[root@localhost linux]# ls
kcore  Makefile  Makefile.enterprise  module.c
```



直接使用make命令进行编译module.dwarf

```
#使用make进行编译
[root@localhost linux]# make
make -C //lib/modules/4.18.0-348.7.1.el8_5.x86_64/build CONFIG_DEBUG_INFO=y M="/tools/volatility/tools/linux" modules
make[1]: 进入目录“/usr/src/kernels/4.18.0-348.7.1.el8_5.x86_64”
  CC [M]  /tools/volatility/tools/linux/module.o
  Building modules, stage 2.
  MODPOST 1 modules
WARNING: modpost: missing MODULE_LICENSE() in /tools/volatility/tools/linux/module.o
see include/linux/module.h for more information
  CC      /tools/volatility/tools/linux/module.mod.o
  LD [M]  /tools/volatility/tools/linux/module.ko
make[1]: 离开目录“/usr/src/kernels/4.18.0-348.7.1.el8_5.x86_64”
dwarfdump -di module.ko > module.dwarf
make -C //lib/modules/4.18.0-348.7.1.el8_5.x86_64/build M="/tools/volatility/tools/linux" clean
make[1]: 进入目录“/usr/src/kernels/4.18.0-348.7.1.el8_5.x86_64”
  CLEAN   /tools/volatility/tools/linux/.tmp_versions
  CLEAN   /tools/volatility/tools/linux/Module.symvers
make[1]: 离开目录“/usr/src/kernels/4.18.0-348.7.1.el8_5.x86_64”

#如果目录下出现module.dwarf则表示编译成功了
[root@localhost linux]# ls
kcore  Makefile  Makefile.enterprise  module.c  module.dwarf
```





查看"/boot目录"，可以发现有

System.map-4.18.0-348.7.1.el8_5.x86_64

System.map-4.18.0-348.el8.x86_64

官方文档说如果系统升级过，可能会有多个System.map文件

![image-20231115164728921](images/Volatility2%20Profile.assets/image-20231115164728921.png)

与uname -a中的进行比对，这里选择第一个

```
[root@localhost /]# ls /boot/
config-4.18.0-348.7.1.el8_5.x86_64                       loader
config-4.18.0-348.el8.x86_64                             symvers-4.18.0-348.7.1.el8_5.x86_64.gz
efi                                                      symvers-4.18.0-348.el8.x86_64.gz
grub2                                                    System.map-4.18.0-348.7.1.el8_5.x86_64
initramfs-0-rescue-bcc543b0985d4003815d73d841bca13f.img  System.map-4.18.0-348.el8.x86_64
initramfs-4.18.0-348.7.1.el8_5.x86_64.img                vmlinuz-0-rescue-bcc543b0985d4003815d73d841bca13f
initramfs-4.18.0-348.7.1.el8_5.x86_64kdump.img           vmlinuz-4.18.0-348.7.1.el8_5.x86_64
initramfs-4.18.0-348.el8.x86_64.img                      vmlinuz-4.18.0-348.el8.x86_64
initramfs-4.18.0-348.el8.x86_64kdump.img
```



打包module.dwarf和System.map-4.18.0-348.7.1.el8_5.x86_64 为zip

```
[root@localhost /]# zip linux_centos8_5_kernel_4_18.zip /boot/System.map-4.18.0-348.7.1.el8_5.x86_64 /tools/volatility/tools/linux/module.dwarf 
  adding: boot/System.map-4.18.0-348.7.1.el8_5.x86_64 (deflated 79%)
  adding: tools/volatility/tools/linux/module.dwarf (deflated 91%)
```



将打包后的zip拷贝到volatility/volatility/plugins/overlays/linux

```
[root@localhost /]# cp -p linux_centos8_5_kernel_4_18.zip /tools/volatility/volatility/plugins/overlays/linux/.
```



使用volatility --info命令查看是否导入成功

![image-20231115161248024](images/Volatility2%20Profile.assets/image-20231115161248024.png)



芜湖！！！！！！！！！！！！！！！！！！！！！！！！！就差一步

![image-20231115162653319](images/Volatility2%20Profile.assets/image-20231115162653319.png)



emmmmmmmmmmmmmmmmmmmmmmmm.............



volatility2官方对于profile中的介绍，其中有一点提到了dwarfdump版本过低导致，制作出来的profile有问题。

而我使用的是最新的版本dwarfdump（0.8）（ 2023-09-20发布），但是centos8操作系统是2021年发布的。

我在想是不是我的版本太高了也会导致问题，所以使用重新编译了dwarfdump（0.1）（2021年发布）版本，然后重新编译了module.dwarf。

制作好了.zip拷贝到了相应目录中，再次使用volatility2，还是出现了问题，但起码不是python报错了，按照此时的报错可能是格式问题。

在上面制作内存转储文件的时候使用的是raw格式，尝试使用lime格式看一下



![image-20231115173143537](images/Volatility2%20Profile.assets/image-20231115173143537.png)



重新制作内存转储文件，使用lime格式

```
[root@localhost mem]# insmod lime-4.18.0-348.7.1.el8_5.x86_64.ko "path=/root/mem/linux.mem format=lime"
```



对新的文件使用volatility2进行测试，发现已经可以正常识别CPU核心数量可，但是一些其他的CPU信息还是无法识别

查看官方文档，说即使制作了对应的profile也有可能有一些插件无法正常使用，目前来说没有什么好的解决方法

![image-20231115173417831](images/Volatility2%20Profile.assets/image-20231115173417831.png)



尝试使用linux_psscan查看进程信息，可以正常查看

但还是有些信息无法正常显示

![image-20231115173925626](images/Volatility2%20Profile.assets/image-20231115173925626.png)



至于为什么 Volatility2 可以识别 lime 格式但不能识别 raw 格式，这可能是因为 lime 格式在每个内存范围前都添加了包含地址空间信息的固定大小的头部，这使得 Volatility2 能够更准确地解析和处理内存转储信息。而 raw 格式由于缺少这些额外的元数据，可能导致 Volatility2 无法正确识别和处理。



尝试使用padded格式

![image-20231115174534953](images/Volatility2%20Profile.assets/image-20231115174534953.png)



参考链接：

https://www.youtube.com/watch?v=qoplmHxmOp4

https://github.com/volatilityfoundation/volatility/wiki/Linux#creating-vtypes