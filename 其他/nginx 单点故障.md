# nginx 单点故障

nginx 单点故障问题

物理网络设备单点故障问题

网络 ISP 链路单点故障问题

入口三网优化

出口三网优化



**学习广播协议**

解决 nginx 单点故障，需要使用到 Keepalived 服务，Keepalived 服务是 VRRP 协议，VRRP 协议通过组播协议进行通讯，组播协议需要物理交换机支持，需要**学习组播协议**。



 使用 x86 linux 作为网络设备，推荐使用什么 linux 操作系统。 





## nginx 单点故障

Nginx 单点故障（Single Point of Failure, SPOF）指的是在系统架构中使用 Nginx 作为核心组件（如反向代理、负载均衡器或 Web 服务器）时，如果 Nginx 服务因某些原因（如硬件故障、软件崩溃、配置错误或网络问题）停止运行，整个系统或服务的可用性会受到严重影响甚至完全中断的情况。



首先学习**双 nginx + Keepalived**  的主备，在学习**双 nginx + Keepalived  的双主**。



**第一个方案**

**本地数据中心（On-Premise）或传统IDC**中最经典、最常用的高可用方案。



使用多台服务器运行 Nginx 实例，使用 Keepalived 通过虚拟 IP（VIP）实现主备切换。

**核心思想**：使用两台或多台 Nginx 服务器，但只有一个“虚拟IP”（Virtual IP, 简称 VIP）对外提供服务。



**部署：**至少两台服务器（一台 Master，一台 Backup），都安装 Nginx 和 Keepalived。

**VIP：**Keepalived 会在这两台服务器之间“漂移”一个 VIP。

**心跳检测**：Master 节点会持续向 Backup 节点发送“心跳”信号。

**故障切换 (Failover)**：

- 当 Backup 节点在规定时间内未收到 Master 的心跳，它会认为 Master 已经宕机。
- Backup 节点会立即“接管”这个 VIP，将 VIP 绑定到自己的网卡上。

**服务恢复**：由于客户端访问的是固定的 VIP，这个切换过程对客户端是透明的，服务会短暂中断后（通常是几秒内）自动恢复。

**优点**：部署相对简单，技术成熟，切换速度快。

**缺点**：

- Master 节点在正常工作时，Backup 节点处于空闲状态，造成资源浪费（除非配置为双主模式，但那会增加复杂性）。
- 依赖 L2 网络（二层广播），在某些复杂的云网络环境中可能受限。



**方案二**

**负载均衡方案 (推荐用于云环境)**

使用云服务商提供的“负载均衡器”（Load Balancer, 如 阿里云的SLB, AWS的ELB）来代替 Keepalived 的 VIP。



**方案三**

**DNS 故障转移 (DNS Failover)**

这种方案适用于需要跨地域（例如不同机房、不同云厂商）容灾的场景。

- **核心思想**：利用智能 DNS 服务，根据服务器的健康状况动态解析域名。
- **工作原理**：
  1. **部署**：你在两个（或多个）地方部署 Nginx 服务器，它们有各自独立的公网 IP。
  2. **DNS配置**：使用支持健康检查的 DNS 服务（如 Cloudflare, AWS Route 53, 阿里云解析DNS）。
  3. **监控**：DNS 服务商的监控节点会从全球多地检查你所有 Nginx 服务器的健康状况。
  4. **切换**：当 DNS 服务发现“主”服务器的 IP 无法访问时，它会自动修改 DNS A 记录，将域名解析到“备”服务器的 IP 地址。
- **优点**：可以实现跨机房、跨地域的容灾。
- **缺点**：
  - **切换慢**：DNS 生效依赖 TTL（Time To Live）缓存时间。即使你设置了很短的 TTL（如 60 秒），但各地的 Local DNS 缓存未必会严格遵守，导致切换可能需要几分钟到几十分钟不等。
  - 切换期间服务中断时间较长。



**方案四**

**硬件负载均衡器 (F5, A10等)**

这适用于大型企业或对性能要求极高的数据中心。

- **核心思想**：使用专门的物理设备（如 F5 BIG-IP）来分发流量。
- **工作原理**：类似于云负载均衡器，但它是你自购的硬件。流量先进 F5，F5 再转发给后端的 Nginx 集群，并负责健康检查。
- **优点**：性能极高，功能强大。
- **缺点**：
  - **昂贵**：设备本身和维护成本都非常高。
  - **新的单点**：硬件负载均衡器自身也可能成为单点故障，所以通常需要购买两台 F5 设备来做它们自己的主备。



## nginx + Keepalived 主备

nginx-1 和 nginx-2 安装 Keepalived 

```
apk add keepalived 
```



在 nginx-1 和 nginx-2 创建配置文件。

```
mkdir /etc/keepalived
vim /etc/keepalived/keepalived.conf
```



在 nginx-1 配置文件中写入以下内容：

```
global_defs {
    router_id NGINX_NODE1   # 主节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -20              # 失败时降低优先级 20
}

vrrp_instance VI_1 {
    state MASTER            # 主节点状态
    interface eth1          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（两节点一致）
    priority 100            # 优先级（主节点较高）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（两节点一致）
    }
    virtual_ipaddress {
        10.33.1.100/24     # 虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}

```



在 nginx-2 配置文件中写入以下内容：

```
global_defs {
    router_id NGINX_NODE2  # 备节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -20              # 失败时降低优先级 20
}

vrrp_instance VI_1 {
    state BACKUP            # 备节点状态
    interface eth1          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（与主节点一致）
    priority 90             # 优先级（低于主节点）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（与主节点一致）
    }
    virtual_ipaddress {
        10.33.1.100/24     # 虚拟 IP（与主节点一致）
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}
```



在 nginx-1 和 nginx-2 上启动 keepalived 并设置为开机自启动。

```
rc-service nginx start
rc-update add nginx default
```



测试：

正常状态下访问 10.33.1.100

```
# curl -i http://10.33.1.100
HTTP/1.1 200 OK
Server: nginx
...

nginx-1
```



在 nginx-1 上手动停止 nginx 服务，模拟 nginx-1 节点故障的场景。

```
rc-service nginx stop
```



在 nginx-1 节点故障的情况下访问 10.33.1.100

```
curl -i http://10.33.1.100
HTTP/1.1 200 OK
Server: nginx
...

nginx-2
```



## nginx + Keepalived 主主

要将 Nginx 和 Keepalived 的配置从主备模式改为**主主模式**（即双主模式），需要为每个节点配置两个 VRRP 实例（vrrp_instance），让每个节点同时作为某个虚拟 IP 的主节点和另一个虚拟 IP 的备节点。这样，两个节点都可以处理流量，实现负载均衡和高可用。



nginx-1 和 nginx-2 安装 Keepalived 

```
apk add keepalived 
```



在 nginx-1 和 nginx-2 创建配置文件。

```
mkdir /etc/keepalived
vim /etc/keepalived/keepalived.conf
```



在主主模式中：

- 每个节点同时为主节点和备节点，分别绑定不同的虚拟 IP。
- 例如，nginx-1 是 VIP1 的主节点、VIP2 的备节点；nginx-2 是 VIP2 的主节点、VIP1 的备节点。
- 需要两个虚拟 IP（如 10.33.1.100 和 10.33.1.200）。



在 nginx-1 上配置 `/etc/keepalived/keepalived.conf`

```
global_defs {
    router_id NGINX_NODE1   # 节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -20              # 失败时降低优先级 20
}

# 第一个 VRRP 实例，nginx-1 为主
vrrp_instance VI_1 {
    state MASTER            # 主状态
    interface eth1          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID
    priority 100            # 优先级（高于 nginx-2）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码
    }
    virtual_ipaddress {
        10.33.1.100/24     # 第一个虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}

# 第二个 VRRP 实例，nginx-1 为备
vrrp_instance VI_2 {
    state BACKUP            # 备状态
    interface eth1          # 网卡名称
    virtual_router_id 52    # 虚拟路由器 ID（与 VI_1 不同）
    priority 90             # 优先级（低于 nginx-2）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码
    }
    virtual_ipaddress {
        10.33.1.200/24     # 第二个虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}
```



在 nginx-2 上配置 `/etc/keepalived/keepalived.conf`

```
global_defs {
    router_id NGINX_NODE2   # 节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -20              # 失败时降低优先级 20
}

# 第一个 VRRP 实例，nginx-2 为备
vrrp_instance VI_1 {
    state BACKUP            # 备状态
    interface eth1          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（与 nginx-1 的 VI_1 一致）
    priority 90             # 优先级（低于 nginx-1）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码
    }
    virtual_ipaddress {
        10.33.1.100/24     # 第一个虚拟 IP（与 nginx-1 的 VI_1 一致）
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}

# 第二个 VRRP 实例，nginx-2 为主
vrrp_instance VI_2 {
    state MASTER            # 主状态
    interface eth1          # 网卡名称
    virtual_router_id 52    # 虚拟路由器 ID（与 nginx-1 的 VI_2 一致）
    priority 100            # 优先级（高于 nginx-1）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码
    }
    virtual_ipaddress {
        10.33.1.200/24     # 第二个虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}
```



在 nginx-1 和 nginx-2 上启动 keepalived 并设置为开机自启动。

```
rc-service keepalived start
rc-update add keepalived default
```



测试

正常情况下访问 **10.33.1.100** 和 **10.33.1.200**

```
# curl http://10.33.1.100 
nginx-1

# curl http://10.33.1.200
nginx-2
```

此时 10.33.1.100 返回 nginx-1，10.33.1.200 返回 nginx-2



手动停止 nginx-1 上的 nginx 服务，模拟 nginx-1 节点故障。

访问 **10.33.1.100** 和 **10.33.1.200**

```
# curl http://10.33.1.100 
nginx-2

# curl http://10.33.1.200
nginx-2
```

此时 10.33.1.100 返回 nginx-2，10.33.1.200 返回 nginx-2



再次启动 nginx-1 上的 nginx 服务，手动停止 nginx-2 上的 nginx 服务，模拟 nginx-2 节点故障。

访问 **10.33.1.100** 和 **10.33.1.200**

```
# curl http://10.33.1.100 
nginx-1

# curl http://10.33.1.200 
nginx-1
```

此时 10.33.1.100 返回 nginx-1，10.33.1.200 返回 nginx-1



### 负载均衡

假设网关服务器上存在公网 IP **11.22.33.44**，配置 iptables 规则，发送给 **11.22.33.44 TCP 80** 的流量负载均衡到 **10.33.1.100** 和 **10.33.1.200** 上。

```bash
# 规则 1：50% 概率将本机发往 11.22.33.44:80 的流量 DNAT 到 10.33.1.100:80
iptables -t nat -A OUTPUT -p tcp -d 11.22.33.44 --dport 80 -m statistic --mode random --probability 0.5 -j DNAT --to-destination 10.33.1.100:80

# 规则 2：剩余流量 DNAT 到 10.33.1.200:80
iptables -t nat -A OUTPUT -p tcp -d 11.22.33.44 --dport 80 -j DNAT --to-destination 10.33.1.200:80
```

```bash
iptables -t nat -A PREROUTING -p tcp -d 11.22.33.44 --dport 80 -m statistic --mode random --probability 0.5 -j DNAT --to-destination 10.33.1.100:80

iptables -t nat -A PREROUTING -p tcp -d 11.22.33.44 --dport 80 -j DNAT --to-destination 10.33.1.200:80
```



测试

正常情况下测试 5 次：

```
# curl http://11.22.33.44
nginx-1

# curl http://11.22.33.44
nginx-1

# curl http://11.22.33.44
nginx-2

# curl http://11.22.33.44
nginx-2

# curl http://11.22.33.44
nginx-1
```



模拟 nginx-1 节点故障后，测试五次

```
# curl http://11.22.33.44
nginx-2

# curl http://11.22.33.44
nginx-2

# curl http://11.22.33.44
nginx-2

# curl http://11.22.33.44
nginx-2

# curl http://11.22.33.44
nginx-2
```



再次启动 nginx-1 ，模拟 nginx-2节点故障后，测试五次

```
# curl http://11.22.33.44
nginx-1

# curl http://11.22.33.44
nginx-1

# curl http://11.22.33.44
nginx-1

# curl http://11.22.33.44
nginx-1

# curl http://11.22.33.44
nginx-1
```



## 主备备配置文件

nginx-1

```
global_defs {
    router_id NGINX_NODE1   # 主节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -30              # 失败时降低优先级 20
}

vrrp_instance VI_1 {
    state MASTER            # 主节点状态
    interface eth1          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（两节点一致）
    priority 100            # 优先级（主节点较高）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（两节点一致）
    }
    virtual_ipaddress {
        10.33.1.100/24     # 虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}
```



nginx-2

```
global_defs {
    router_id NGINX_NODE1   # 主节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -30              # 失败时降低优先级 20
}

vrrp_instance VI_1 {
    state MASTER            # 主节点状态
    interface eth1          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（两节点一致）
    priority 90            # 优先级（主节点较高）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（两节点一致）
    }
    virtual_ipaddress {
        10.33.1.100/24     # 虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}
```



nginx-3

```
global_defs {
    router_id NGINX_NODE1   # 主节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -30              # 失败时降低优先级 20
}

vrrp_instance VI_1 {
    state MASTER            # 主节点状态
    interface eth1          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（两节点一致）
    priority 80            # 优先级（主节点较高）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（两节点一致）
    }
    virtual_ipaddress {
        10.33.1.100/24     # 虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}
```

