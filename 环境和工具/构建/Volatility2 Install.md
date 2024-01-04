# Volatility 2

```
pip2 install pycrypto
pip2 install distorm3


[root@localhost volatility2]# python2 vol.py -h
Volatility Foundation Volatility Framework 2.6.1
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/root/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --info                Print information about all registered objects
  --cache-directory=/root/.cache/volatility
                        Directory where cache files are stored
  --cache               Use caching
......
```



# 编写shell脚本添加到/usr/local/bin

```
[root@localhost bin]# pwd
/usr/local/bin

#vol2
[root@localhost bin]# cat vol2 
#!/bin/bash
# 定义Volatility的路径
VOLATILITY_PATH="/tools/volatility2/vol.py"

# 调用Volatility并传递所有的命令行参数
python2 $VOLATILITY_PATH "$@"

```

