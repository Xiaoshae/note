# Docker 容器管理

## Run

语法：`docker run [OPTIONS] IMAGE [COMMAND] [ARG...]`
作用：创建一个新的容器，并指定参数

```

选项：
      --add-host list 添加自定义主机到 IP 的映射 (host:ip)
  -a, --attach list 附加到 STDIN、STDOUT 或 STDERR
      --blkio-weight uint16 块 IO（相对权重），10 到 1000 之间，或 0 禁用（默认 0）
      --blkio-weight-device list 块 IO 权重（相对设备权重）（默认 []）
      --cap-add list 添加 Linux 功能
      --cap-drop list 删除 Linux 功能
      --cgroup-parent string 容器的可选父 cgroup
      --cgroupns 字符串要使用的 Cgroup 命名空间（主机|私有）
             ‘host’：在 Docker 主机的 cgroup 命名空间中运行容器
             'private'：在自己的私有 cgroup 命名空间中运行容器
             ''：使用配置的 cgroup 命名空间
             守护进程上的 default-cgroupns-mode 选项（默认）
      --cidfile string 将容器 ID 写入文件
      --cpu-period int 限制 CPU CFS（完全公平调度程序）周期
      --cpu-quota int 限制 CPU CFS（完全公平调度程序）配额
      --cpu-rt-period int 以微秒为单位限制 CPU 实时周期
      --cpu-rt-runtime int 以微秒为单位限制 CPU 实时运行时间
  -c, --cpu-shares int CPU 份额（相对权重）
      --cpus 十进制 CPU 数
      --cpuset-cpus string 允许执行的 CPU (0-3, 0,1)
      --cpuset-mems 字符串 允许执行的 MEMs (0-3, 0,1)
  -d, --detach 在后台运行容器并打印容器 ID
      --detach-keys string 覆盖分离容器的键序列
      --device list 将主机设备添加到容器中
      --device-cgroup-rule list 添加规则到 cgroup 允许的设备列表
      --device-read-bps list 限制从设备的读取速率（每秒字节数）（默认 []）
      --device-read-iops list 限制从设备的读取速率（每秒 IO）（默认 []）
      --device-write-bps list 限制设备的写入速率（每秒字节数）（默认 []）
      --device-write-iops list 限制设备的写入速率（每秒 IO）（默认 []）
      --disable-content-trust 跳过图像验证（默认为 true）
      --dns list 设置自定义 DNS 服务器
      --dns-option list 设置 DNS 选项
      --dns-search list 设置自定义 DNS 搜索域
      --domainname string 容器 NIS 域名
      --entrypoint string 覆盖图片的默认ENTRYPOINT
  -e, --env list 设置环境变量
      --env-file list 读入环境变量文件
      --expose list 公开一个端口或一系列端口
      --gpus gpu-request GPU devices to add to the container ('all' to pass all GPUs)
      --group-add list 添加要加入的其他组
      --health-cmd string 运行检查健康状况的命令
      --health-interval duration 运行检查之间的时间（ms|s|m|h）（默认为 0s）
      --health-retries int 报告不健康所需的连续失败
      --health-start-period duration 容器在开始健康重试之前初始化的开始时间
                                       倒计时 (ms|s|m|h)（默认 0s）
      --health-timeout duration 允许一次检查运行的最长时间（ms|s|m|h）（默认为 0s）
      --help 打印用法
  -h, --hostname string 容器主机名
      --init 在容器内运行一个 init 来转发信号和收割进程
  -i, --interactive 保持 STDIN 打开，即使没有连接
      --ip 字符串 IPv4 地址（例如 172.30.100.104）
      --ip6 字符串 IPv6 地址（例如，2001:db8::33）
      --ipc string 要使用的 IPC 模式
      --isolation string 容器隔离技术
      --kernel-memory bytes 内核内存限制
  -l, --label list 在容器上设置元数据
      --label-file list 读入一行分隔的标签文件
      --link list 添加到另一个容器的链接
      --link-local-ip list 容器 IPv4/IPv6 链路本地地址
      --log-driver string 容器的日志驱动
      --log-opt list 日志驱动程序选项 
      --mac-address string 容器 MAC 地址（例如，92:d0:c6:0a:29:33）
  -m, --memory bytes 内存限制
      --memory-reservation bytes 内存软限制
      --memory-swap 字节交换限制等于内存加交换：'-1'启用无限交换
      --memory-swappiness int 调整容器内存交换（0 到 100）（默认 -1）
      --mount mount 将文件系统挂载到容器
      --name string 为容器指定一个名称
      --network network 将容器连接到网络
      --network-alias list 为容器添加网络范围的别名
      --no-healthcheck 禁用任何容器指定的 HEALTHCHECK
      --oom-kill-disable 禁用 OOM 杀手
      --oom-score-adj int 调整主机的 OOM 首选项（-1000 到 1000）
      --pid string 要使用的 PID 命名空间
      --pids-limit int 调整容器 pids 限制（设置 -1 表示无限制）
      --platform string 如果服务器支持多平台，则设置平台
      --privileged 赋予此容器扩展权限
  -p, --publish list 将容器的端口发布到主机
  -P, --publish-all 将所有暴露的端口发布到随机端口
      --pull string 运行前拉取镜像 ("always"|"missing"|"never") (默认 "missing")
      --read-only 将容器的根文件系统挂载为只读
      --restart string 在容器退出时应用重启策略（默认为“no”）
      --rm 退出时自动移除容器
      --runtime string 用于此容器的运行时
      --security-opt 列表安全选项
      --shm-size bytes /dev/shm 的大小
      --sig-proxy 代理接收到进程的信号（默认为真）
      --stop-signal string 停止容器的信号（默认“SIGTERM”）
      --stop-timeout int 停止容器的超时（以秒为单位）
      --storage-opt list 容器的存储驱动程序选项
      --sysctl 映射 Sysctl 选项（默认映射 []）
      --tmpfs list 挂载一个tmpfs目录
  -t, --tty 分配一个伪 TTY
      --ulimit ulimit Ulimit 选项（默认 []）
  -u, --user string 用户名或 UID（格式：<name|uid>[:<group|gid>]）
      --userns string 要使用的用户命名空间
      --uts 字符串要使用的 UTS 命名空间
  -v, --volume list 绑定挂载一个卷
      --volume-driver string 容器的可选卷驱动程序
      --volumes-from list 从指定容器挂载卷
  -w, --workdir string 容器内的工作目录
```



## 常规

设置容器的名称

```
docker run --name test -d centos:latest
```



设置环境变量

```
docker run --rm -d -e   PORT=80 centos:latest
docker run --rm -d -env PORT=80 centos:latest
```



指定容器中的工作路径

```
docker run --rm -d -w /etc/nginx centos:latest
```



指定容器启动时自动执行的命令（或脚本）

```
docker run --rm -d -w /etc/nginx centos:latest ./run.sh
```



## 网络

设置网络为 host ，与主句使用相同网络

```
docker run --rm -d --network host centos:latest
```



将外部端口80映射到容器中的8080端口。

```
docker run --rm -d -p 80:8080 centos:latest
```



指定IP地址

```
docker run --rm -d -p 0.0.0.0:80:8080 centos:latest
```



指定tcp/udp协议

```
docker run --rm -d -p 0.0.0.0:80:8080/tcp centos:latest
docker run --rm -d -p 8080:80/udp centos:latest
```



## 存储

将主机文件/文件夹挂载到容器中

```
docker run --rm -d -v /docker/test:/etc/test centos:latest
```



