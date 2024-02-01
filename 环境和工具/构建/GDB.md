

# 编译环境

## gcc

```
dnf -y groupinstall "开发工具" "传统 UNIX 兼容性"
dnf install -y glibc-devel.i686 libstdc++-devel.i686 

dnf -y install gmp gmp-devel
dnf -y install mpfr mpfr-devel
```



## makeinfo(textinfo)

```
#解压
tar -xf texinfo-6.6.tar.xz 
cd texinfo-6.6/

#构建环境目录
mkdir build
cd build

#初始化
../configure

#编译
make -j16

#安装
make install
```



## Ubuntu

```
#编译环境
apt-get install build-essential

# 安装32位环境
sudo apt-get install lib32readline-dev

# 安装 gmp 和 gmp-devel
sudo apt-get install libgmp3-dev

# 安装 mpfr 和 mpfr-devel
sudo apt-get install libmpfr-dev

# 安装 texinfo
sudo apt-get install texinfo
```



## gdb

python环境

```
dnf install python3 -y
dnf install python36 -y
dnf install python39 -y

dnf install python36-devel -y
dnf install python39-devel -y
```



```
#解压源码
tar -xf gdb-13.2.tar.xz 
cd gdb-13.2/

#预构建
mkdir build
cd build/

#初始化
../configure --prefix=/tools/gdb13.2/ --with-python=/usr/bin/python3.9

#编译
make -j16
```



# gef插件

