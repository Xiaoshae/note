

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

