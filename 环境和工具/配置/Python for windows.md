# 安装pip

python for windows 便携式解压包安装

去下载对应版本的 get-pip.py 文件，这里以python3.6举例

```
https://bootstrap.pypa.io/pip/3.6/get-pip.py
```



前往python3.6的安装路径

使用python安装pip

```
python.exe get-pip.py
```

如果下载太慢了可以-i指定国内镜像，这里使用 清华pipy镜像

```
python.exe get-pip.py -i https://pypi.tuna.tsinghua.edu.cn/simple
```



安装pip成功后需要修改，python安装路径的文件

修改下面这个文件

```
python39._pth
```

在这个文件的最后面加上，下面这段

```
Lib\site-packages
```

