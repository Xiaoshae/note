# Learn to Hack! (Part 2)

Youtube视频：https://www.youtube.com/watch?v=sH4JCwjybGs

# 信息收集

## 子域名扫描

其他子域名信息收集工具：

域名证书指纹：crt.sh

子域名工具：https://www.virustotal.com/



### sublist

Github项目地址：https://github.com/aboul3la/Sublist3r

注：这个项目在Github上已经很久没有更新过了，最后一次commit在2020年，不建议继续使用了。



使用帮助：

```
用法: sublist3r.py [-h] -d 域名 [-b [BRUTEFORCE]] [-p 端口] [-v [VERBOSE]]
                    [-t 线程数] [-e 引擎] [-o 输出文件] [-n]

选项:
  -h, --help            显示此帮助消息并退出
  -d 域名, --domain 域名
                        要枚举其子域名的域名名称
  -b [BRUTEFORCE], --bruteforce [BRUTEFORCE]
                        启用subbrute暴力破解模块
  -p 端口, --ports 端口
                        使用指定的TCP端口扫描找到的子域名
  -v [VERBOSE], --verbose [VERBOSE]
                        启用详细输出，并实时显示结果
  -t 线程数, --threads 线程数
                        为subbrute暴力破解使用的线程数量
  -e 引擎, --engines 引擎
                        指定以逗号分隔的搜索引擎列表
  -o 输出文件, --output 输出文件
                        将结果保存到文本文件中
  -n, --no-color        不带颜色的输出
  
例子: python /root/envir/Sublist3r/sublist3r.py -d google.com
```



例子：

```
sublist3r -v -d google.com -b -t 16 -e Baidu,Bing -o ./output.txt
```



### amass

Github项目地址：https://github.com/owasp-amass/amass



使用帮助：

```

        .+++:.            :                             .+++.
      +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+
     &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&
    +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8
    8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:
    WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:
    #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8
    o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.
     WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o
     :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+
      :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&
        +o&&&&+.                                                    +oooo.

                                                                      v4.2.0
                                           OWASP Amass 项目 - @owaspamass
                           深度攻击面映射和资产发现

用法：amass enum [选项] -d 域名

  -active
        尝试区域传输和证书名称抓取
  -addr 值
        IP 和范围（192.168.1.1-254）以逗号分隔
  -alts
        启用生成修改后的名称
  -asn 值
        AS 编号以逗号分隔（可多次使用）
  -aw 值
        修改名称时使用的不同字典文件路径
  -awm 值
        “hashcat 风格”的字典掩码用于名称修改
  -bl 值
        不进行调查的子域名黑名单
  -blf 字符串
        提供黑名单子域的文件路径
  -brute
        在搜索后执行暴力破解
  -cidr 值
        CIDR 块以逗号分隔（可多次使用）
  -config 字符串
        YAML 配置文件的路径。更多细节见下文
  -d 值
        以逗号分隔的域名（可多次使用）
  -demo
        审查输出使其适合演示
  -df 值
        提供根域名的文件路径
  -dir 字符串
        包含输出文件的目录路径
  -dns-qps 整数
        所有解析器上每秒最大 DNS 查询次数
  -ef 字符串
        提供要排除数据源的文件路径
  -exclude 值
        要排除的数据源名称，以逗号分隔
  -h    显示程序使用信息
  -help
        显示程序使用信息
  -if 字符串
        提供要包含数据源的文件路径
  -iface 字符串
        提供发送流量通过的网络接口
  -include 值
        要包含的数据源名称，以逗号分隔
  -list
        打印所有可用数据源的名称
  -log 字符串
        错误将被写入的日志文件路径
  -max-depth 整数
        暴力破解的最大子域名标签数
  -max-dns-queries 整数
        已废弃标志，将在版本 4.0 中由 dns-qps 替换
  -min-for-recursive 整数
        触发递归暴力破解前需要观察到的子域名标签数（默认：1）（默认值 1）
  -nf 值
        提供已知子域名名称的文件路径（来自其他工具/来源）
  -nocolor
        禁用彩色输出
  -norecursive
        关闭递归暴力破解
  -o 字符串
        包含终端标准输出/错误的文本文件路径
  -oA 字符串
        用于命名所有输出文件的路径前缀
  -p 值
        以逗号分隔的端口（默认：80, 443）
  -passive
        已废弃，被动模式是默认设置
  -r 值
        不信任的 DNS 解析器的 IP 地址（可多次使用）
  -rf 值
        提供不信任的 DNS 解析器的文件路径
  -rqps 整数
        对于每个不信任的解析器，每秒最大 DNS 查询次数
  -scripts 字符串
        包含 ADS 脚本的目录路径
  -silent
        执行期间禁用所有输出
  -timeout 整数
        枚举运行前退出的分钟数
  -tr 值
        可信 DNS 解析器的 IP 地址（可多次使用）
  -trf 值
        提供可信 DNS 解析器的文件路径
  -trqps 整数
        对于每个可信的解析器，每秒最大 DNS 查询次数
  -v    输出状态/调试/故障排查信息
  -w 值
        暴力破解时使用的不同字典文件路径
  -wm 值
        “hashcat 风格”的字典掩码用于 DNS 暴力破解

用户指南可以在这里找到：
https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md

示例配置文件可以在这里找到：
https://github.com/owasp-amass/amass/blob/master/examples/config.yaml

Amass 教程可以在这里找到：
https://github.com/owasp-amass/amass/blob/master/doc/tutorial.md
```



