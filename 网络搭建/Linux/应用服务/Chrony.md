# Chrony

Chrony 是一个实现 NTP（网络时间协议） 的时间同步工具，用于同步本地系统时间与远程时间服务器的时间。

Chrony 支持两种角色：

- **客户端**：从外部 NTP 服务器同步时间。
- **服务端**：为内网其他主机提供时间同步服务。



Chrony 使用 NTP（网络时间协议）进行时间同步。NTP 协议传输的时间始终是 UTC 时间（协调世界时，Coordinated Universal Time）。NTP 服务器不传递时区信息，仅提供精确的 UTC 时间戳。



CentOS 8 中安装 Chrony：

```
dnf install chrony
```





## 配置文件



### server

```
server <NTP服务器> [选项]
```

指定外部 NTP 服务器地址，用于客户端同步时间。常用选项：

- **iburst**：在首次同步时发送多个数据包以加速同步。
- **minpoll <秒>**：设置最小轮询间隔（以秒为单位，2^n）。
- **maxpoll <秒>**：设置最大轮询间隔（以秒为单位，2^n）。



### pool

```
server < NTP服务器 1 > < NTP服务器 2 > ... [选项]
```

指定一组 NTP 服务器池（如 pool.ntp.org），自动选择可用服务器。选项与 server 相同。

Chrony 会同时尝试从 server 和 pool 指定的所有服务器同步时间，并根据服务器的可靠性、延迟和 stratum 值选择最佳时间源。



### allow

```
allow [IP/子网]
```

允许指定 IP 或子网的客户端访问本机的 NTP 服务，用于服务端配置。 示例：



### local

```
local stratum <层级>
```

启用本地时间服务，即使与外部 NTP 服务器失联，仍然作为时间源为内网提供服务。<层级> 通常设为 10 或更高。



Stratum 是 NTP 协议中的一个概念，用于表示时间源与高精度时间参考（如 GPS 或原子钟）的距离：

- **Stratum 1**：直接与高精度时间源（如 GPS 或原子钟）同步的服务器。
- **Stratum 2**：从 Stratum 1 同步时间的服务器。
- **Stratum 3 及以上**：依次递增，每经过一层同步，Stratum 值加 1。



**正常情况下**：

- Chrony 作为客户端，从外部 NTP 服务器（如 pool.ntp.org）同步时间。
- Chrony 作为服务端，为内网客户端提供时间同步，Stratum 层级通常是外部服务器的 Stratum 值加 1（例如，外部服务器是 Stratum 2，则本地服务器是 Stratum 3）。



**与外部服务器失联时**：

- Chrony 检测到所有配置的外部 NTP 服务器（server 或 pool）都不可用。
- 如果配置了 local stratum <层级>，Chrony 会切换到本地时间源模式，使用本机的系统时钟作为时间参考。
- Chrony 以指定的 Stratum 层级（如 10）向内网客户端提供时间。
- 本地时间源的精度取决于系统时钟的稳定性，通常不如外部 NTP 服务器精确，但足以维持内网时间的一致性。



**恢复连接后**：

- 当外部 NTP 服务器恢复可用时，Chrony 会重新与它们同步，并恢复从外部服务器获取时间的正常模式。
- 客户端会自动切换到更低的 Stratum 层级（即更可靠的时间源）。



当配置 local stratum <层级> 时，通常选择一个较高的 Stratum 值（如 10 或更高），以表明本地时间源的可靠性低于真正的外部 NTP 服务器。

如果 Stratum 值设置过低（如 2 或 3），内网客户端可能优先选择本地时间源，而忽略更可靠的外部 NTP 服务器（当外部服务器可用时）。

高 Stratum 值（如 10）确保客户端在外部服务器可用时优先使用它们，只有在外部服务器不可用时才 fallback 到本地时间源。



### makestep

```
makestep <阈值> <次数>
```

如果时间偏差超过 <阈值> 秒，强制调整时间（而不是平滑校正）。<次数> 表示允许强制调整的次数（-1 表示无限制）。 





### rtcsync

启用硬件时钟（RTC）与系统时间的同步。



> Linux 默认将硬件时钟设置为 **UTC 时间**，并通过系统时区设置将 UTC 时间转换为本地时间显示。
>
> Windows 将硬件时钟设置为**本地时间（即根据系统设置的时区计算后的时间）**，而不是 UTC 时间。
>
> 注意：这种差异在双系统（Windows 和 Linux）环境中导致时间不一致问题。



## 时间管理

### 设置时间

如果需要手动设置时间（不推荐，除非 NTP 未启用）：

```
timedatectl set-time "2025-06-13 15:50:00"
```



date 命令，查看当前系统时间：

```
date
```

**输出示例**：

```
Fri Jun 13 15:50:23 HKT 2025
```



设置时间（不推荐，除非禁用 NTP）：

```
sudo date -s "2025-06-13 15:50:00"
```



查看硬件时钟（RTC）时间：

```
hwclock
```

输出示例：

```
2025-06-13 07:50:23.123456+08:00
```



将系统时间同步到硬件时钟：

```
hwclock --systohc
```



将硬件时钟同步到系统时间：

```
hwclock --hctosys
```



### NTP 服务

使用 **timedatectl** 查看时间状态

```
timedatectl
```

```
      Local time: Fri 2025-06-13 15:50:23 HKT
  Universal time: Fri 2025-06-13 07:50:23 UTC
        RTC time: Fri 2025-06-13 07:50:23
       Time zone: Asia/Hong_Kong (HKT, +0800)
 System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
```



**输出字段说明**：

- **Local time**：本地时间。
- **Universal time**：UTC 时间。
- **RTC time**：硬件时钟（Real-Time Clock）时间。
- **Time zone**：当前时区。
- **System clock synchronized**：系统时钟是否与 NTP 服务器同步（yes 表示已同步）。
- **NTP service**：NTP 服务是否启用（active 表示启用）。
- **RTC in local TZ**：硬件时钟是否使用本地时区（通常为 no，表示使用 UTC）。



要确认 NTP 服务是否启用，可以运行：

```
timedatectl show
```

```
Timezone=Asia/Hong_Kong
LocalRTC=no
CanNTP=yes
NTP=yes
NTPSynchronized=yes
TimeUSec=Fri 2025-06-13 15:50:23 HKT
RTCTimeUSec=Fri 2025-06-13 15:50:23 HKT
```

- **NTP=yes**：表示 NTP 服务已启用。
- **NTPSynchronized=yes**：表示系统时间已与 NTP 服务器同步。



当运行 **timedatectl show** 或 **timedatectl** 命令时，如果输出显示 NTP=yes（表示 NTP 服务已启用）但 NTPSynchronized=no（表示系统时间未与 NTP 服务器同步）



启用 NTP 时间同步：

```
timedatectl set-ntp true
```



禁用 NTP 时间同步：

```
timedatectl set-ntp false
```



### 时区

查看所有可用时区：

```
timedatectl list-timezones
```



**过滤特定区域**（例如亚洲）：

```
timedatectl list-timezones | grep Asia
```



更改系统时区，例如设置为上海时区：

```
timedatectl set-timezone Asia/Shanghai
```



## chrony 命令

### 守护进程

确认 chronyd 服务是否正在运行：

```
systemctl status chronyd
```



**输出示例**（部分）：

```
● chronyd.service - NTP client/server
   Loaded: loaded (/usr/lib/systemd/system/chronyd.service; enabled; vendor preset: enabled)
   Active: active (running) since Fri 2025-06-13 15:50:00 HKT; 1h ago
```

- **Active: active (running)**：表示服务正在运行。
- **enabled**：表示服务已配置为开机自启。



启动 chronyd 服务（如果未运行）：

```
sudo systemctl start chronyd
```



启用开机自启：

```
sudo systemctl enable chronyd
```



### 同步状态

运行以下命令查看当前使用的 NTP 服务器：

```
chronyc sources
```



**输出示例**：

```
210 Number of sources = 4
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* ntp1.example.com         2   6   377   64   +15us[+20us] +/-  20ms
^- ntp2.example.com         3   6   377   64   -10us[-15us] +/-  25ms
^+ ntp3.example.com         2   6   377   64   +25us[+30us] +/-  22ms
^+ ntp4.example.com         3   6   377   64   -5us[-10us] +/-  30ms
```

**字段说明**：

- **MS**：
  - **^**：表示服务器。
  - *****：当前正在使用的同步源。
  - **+**：备用同步源。
  - **-**：未使用的源。
- **Stratum**：NTP 服务器的层级（越低越接近高精度时间源）。
- **Poll**：查询间隔（秒）。
- **Reach**：连接成功率（八进制，377 表示 100% 成功）。
- **LastRx**：最后一次接收数据的时间。
- **Last sample**：时间偏差和误差范围。



### 运维

强制同步时间，如果需要立即同步时间：

```
chronyc makestep
```



检查 chrony 客户端连接，查看连接的客户端：

```
chronyc clients
```

输出示例：

```
Hostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last
===============================================================================
client1.example.com           10      0   6   -   64       0      0   -   -
client2.example.com           12      0   6   -   64       0      0   -   -
```









## 示例

### 服务端配置

在作为客户端同步时间的基础上，配置 chrony 为内网其他 Linux 主机提供时间同步服务。



设置时区：

```
timedatectl set-timezone Asia/Hong_Kong
```



确保 chrony 已安装：

```
sudo dnf install chrony
```



编辑 **/etc/chrony.conf** 配置文件：

```shell
# 清空或保留客户端部分的配置
pool pool.ntp.org iburst

# 允许内网子网访问本机 NTP 服务
allow 192.168.1.0/24

# 如果与外部 NTP 服务器失联，仍然提供本地时间
local stratum 10

# 启用硬件时钟同步
rtcsync

# 允许时间步进校正
makestep 1.0 3
```



启动 chronyd 服务并设置为开机自启：

```
sudo systemctl start chronyd
sudo systemctl enable chronyd
```



为 NTP 服务（UDP 123 端口）开放防火墙规则：

```
sudo firewall-cmd --add-service=ntp --permanent
sudo firewall-cmd --reload
```





### 客户端配置

在其他内网 Linux 主机上，配置 chrony 以从服务端（假设服务端 IP 为 192.168.1.10）同步时间。



设置时区：

```
timedatectl set-timezone Asia/shanghai
```



确保客户端已安装 chrony：

```
sudo dnf install chrony
```



编辑客户端的 **/etc/chrony.conf**：

```shell
# 指定服务端的 IP 地址
server 192.168.1.10 iburst

# 启用硬件时钟同步
rtcsync

# 允许时间步进校正
makestep 1.0 3
```



启动 chronyd 服务并设置为开机自启：

```
sudo systemctl start chronyd
sudo systemctl enable chronyd
```





## 常见问题解答

### 没有配置 local stratum

`local stratum <层级>` 是一个可选配置，用于在 Chrony 与外部 NTP 服务器（通过 server 或 pool 指定的上游服务器）失联时，启用本地系统时钟作为时间源，为内网客户端提供时间同步。如果不设置该指令：

本地时间源不会被启用：

- Chrony 不会将本机的系统时钟作为备用时间源。
- 当与所有外部 NTP 服务器失联时，Chrony 将停止向内网客户端提供时间同步服务。



### 防火墙

检查服务器是否开启防火墙，如果开启防火墙，是否配置规则，允许 chrony 服务的入站连接（UDP 123 端口）



查看防火墙状态：

```
systemctl status chrony
```



查看防火墙规则：

```
firewall-cmd --list-services
```

输出中应包含 ntp。



如需验证是否为防火墙导致，临时关闭防火墙（仅用于测试，生产环境不推荐）：

```
systemctl stop firewalld
```

