# Volatility 3

```
#dnf -y install openssl-devel
#sudo apt-get install libssl-dev

pip3 install -r requirements.txt

[root@localhost volatility3]# python3.9 vol.py -h
Volatility 3 Framework 2.5.2
usage: volatility [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]] [-e EXTEND] [-p PLUGIN_DIRS]
                  [-s SYMBOL_DIRS] [-v] [-l LOG] [-o OUTPUT_DIR] [-q] [-r RENDERER] [-f FILE] [--write-config]
                  [--save-config SAVE_CONFIG] [--clear-cache] [--cache-path CACHE_PATH] [--offline]
                  [--single-location SINGLE_LOCATION] [--stackers [STACKERS ...]]
                  [--single-swap-locations [SINGLE_SWAP_LOCATIONS ...]]
                  plugin ...
........
```



# 编写shell脚本添加到/usr/local/bin

```
[root@localhost bin]# pwd
/usr/local/bin

#vol3
[root@localhost bin]# cat vol3
#!/bin/bash
# 定义Volatility的路径
VOLATILITY_PATH="/tools/volatility3/vol.py"

# 调用Volatility并传递所有的命令行参数
python3.9 $VOLATILITY_PATH "$@"
```

