

# kali设置系统语言方法

```
dpkg-reconfigure locales

在出现的列表中，使用空格键选中zh_CN.UTF-8 UTF-8123。
选中后，按下回车键。
在下一个界面中，选择zh_CN.UTF-8作为默认语言。
最后，重启系统以使更改生效
```



# 安装`gcc -m32`安装环境

```
sudo apt-get install lib32readline-dev
```



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

