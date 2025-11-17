# NGINX HA

**NGINX HA**（High Availability），即 **NGINX 高可用性**。

**NGINX HA **是指一种**架构设计或解决方案**，其目标是确保 NGINX 提供的服务（如反向代理、负载均衡）能够**持续不断地运行，即使发生单点硬件或软件故障**。



## 单点故障

如果你的架构中**只有一台 NGINX 服务器（即“单点部署”）**，它就成为了一个**“单点故障” (Single Point of Failure, SPOF)**。

所有的用户请求都必须经过这台 NGINX 服务器才能到达后端的应用服务器 (App Server)。如果这台唯一的 NGINX 服务器因为任何原因（如：电源故障、网卡损坏、NGINX 进程崩溃等）宕机，**整个网站或应用将立即对外瘫痪**，所有用户都无法访问服务。



NGINX HA 就是通过部署**至少两台** NGINX 服务器组成一个集群，解决单点故障。这个集群通常采用**主备模式（Active-Passive）**或**主主模式（Active-Active）**。



**主备模式 (Active-Passive)**：

在任何时间，只有一台 NGINX 服务器（称为“主”或“Active”节点）在实际处理所有用户流量。另一台（或多台）服务器（称为“备”或“Passive”节点）处于待命状态。它会持续监控主节点的状态。

当备用节点检测到主节点“死亡”（例如，宕机、网络中断、NGINX 进程崩溃）时，备用节点会**自动、快速地接管**主节点的工作，开始处理所有流入的流量。**这个过程成为故障转移。**



**主主模式 (Active-Active)**：

集群中的所有 NGINX 服务器都在同时活动，共同分担流量。

这种模式通常需要更高级的负载均衡器（例如云厂商的负载均衡器或 L4 负载均衡器）在 NGINX 集群的前端，将流量分发到所有活动的 NGINX 节点。

如果其中一个 NGINX 节点发生故障，前端的负载均衡器会检测到它，并自动停止向其发送流量，将其余流量分配给其他健康的节点。



## Keepalived + VRRP

**Keepalived + VRRP** 是在本地数据中心（On-Premise）或传统虚拟机（VM）环境中最经典、最常用的方案。

- **Keepalived**：是一个在 Linux 系统上运行的路由软件。它的核心功能就是提供高可用性。
- **VRRP (Virtual Router Redundancy Protocol)**：即“虚拟路由冗余协议”。Keepalived 使用了 VRRP 协议来实现 HA。



**主备模式工作原理：**

1. **虚拟 IP (Virtual IP, VIP)：** 设置一个不属于任何单个服务器的“浮动 IP 地址”，即 VIP。这个 VIP 才是客户端（或 DNS）真正指向的地址。
2. **角色选举：** 在两台安装了 NGINX 和 Keepalived 的服务器上，一台通过 VRRP 选举成为 `MASTER`（主），另一台成为 `BACKUP`（备）。
3. **VIP 归属：** `MASTER` 节点会“持有”这个 VIP。它会主动向网络宣告自身对该 VIP 的所有权，从而接收所有导向该 VIP 的业务流量。所有业务流量均流向 MASTER 节点，`BACKUP` 节点则处于静默状态。
4. **心跳检测：** `MASTER` 节点会周期性地向局域网内广播“心跳”信号（即 VRRP 报文），以宣告自身处于活动状态。BACKUP 节点会持续不断地监听此心跳。
5. **故障转移：** 如果 `BACKUP` 节点在规定时间内（例如3秒）没有收到 `MASTER` 的心跳，它就判定 `MASTER` 已经宕机。此时，`BACKUP` 节点会立即“抢占” VIP（通过发送 gratuitous ARP），接管 `MASTER` 的角色，开始处理流量。



**主主模式工作原理：**

1. **虚拟 IP (VIPs) 与流量分发：** 设置至少两个“浮动 IP 地址”（例如 VIP 1 和 VIP 2）。与主备模式不同，这两个 VIP 同时对外提供服务。客户端（或 DNS）通常通过负载均衡策略（如 DNS 轮询）将流量同时导向这两个 VIP。
2. **角色分配 (VRRP 组)：** 此模式下会配置至少两个 VRRP 实例（组）。例如，服务器 A 被配置为“组1”（对应 VIP 1）的 MASTER 和“组2”（对应 VIP 2）的 BACKUP；服务器 B 的配置则相反，被配置为“组2”的 MASTER 和“组1”的 BACKUP。
3. **VIP 归属与负载均衡：** 在正常情况下，服务器 A“持有”VIP 1 并处理其流量；服务器 B“持有”VIP 2 并处理其流量。由于两个 VIP 均在外部分发流量，因此两台服务器都处于活动状态，共同分担业务负载，实现了负载均衡。
4. **双向心跳检测：** 两台服务器都会为自己作为 MASTER 的 VRRP 组周期性地广播“心跳”信号（VRRP 报文）。同时，它们也互相监听对方（即自己作为 BACKUP 的组）的心跳，以宣告各自的活动状态。
5. **故障转移与接管：** 假设服务器 A 宕机。服务器 B（作为“组1”的 BACKUP）会因未收到服务器 A 的心跳而触发故障转移。服务器 B 会立即“抢占”原属于服务器 A 的 VIP 1（通过发送 gratuitous ARP）。此时，服务器 B 将同时持有 VIP 1 和 VIP 2，独自处理所有的业务流量，确保服务不中断。



## 架构中的其他单点故障

很多人认为部署了 `Keepalived + VRRP` 就万事大吉，实现了高可用（HA），但实际上，这套架构仅仅解决了 **VIP (虚拟IP) / 网关** 的单点故障问题。

一个真正的高可用架构是一个系统工程，`Keepalived` 只是其中的一个环节。如果其他组件存在单点，整个系统的可用性依然会像木桶一样，取决于最短的那块板。



以下是在 Keepalived + VRRP 架构中，其他常见的潜在单点故障 (SPOF)。



### 基础设施单点故障

**接入交换机**

这是最常见、最致命的单点故障。假设为了简单，你将 `NGINX_Master` 和 `NGINX_Backup` **同时插入了同一台接入交换机**。

如果这台交换机突然宕机（电源故障、固件崩溃、端口全坏）。

虽然 Keepalived 的 HA 机制可能在两台机器内部触发了切换（`VRRP` 和 `Backup` 同时拥有 VIP），但这毫无意义，因为它们都成了“孤岛”。VIP 对应的 MAC 地址无法在网络上被学习到，流量在交换机层面就已经中断。**整个高可用集群全军覆没。**



**核心交换机 / 上行链路**

即使做了交换机冗余（`Master` 插在 `Switch-A`，`Backup` 插在 `Switch-B`），但这两台 `Switch-A` 和 `Switch-B` **都连接到同一台核心交换机**。

接入交换机（或交换机堆叠）只有**一条**物理链路连接到**一台核心交换机**。如果**核心交换机**宕机，或者这条**物理链路不可用**或**光模块损坏**，所有通往 NGINX 集群的流量路径全部中断。



**边缘路由器 / 网关**

`Keepalived + NGINX` 集群的上游是**一台**边缘路由器或防火墙，它负责处理所有外部流量。

如果这台路由器宕机，所有来自互联网的流量都无法进入内部网络。NGINX HA 集群（VIP）在内部网络（LAN）中可能是完全可达的，Keepalived 切换也正常。但对于所有外部用户来说，服务已经中断。



**"裂脑" (Split-Brain) - 心跳网络的隔离**

`Master` 插在 `Switch-A`，`Backup` 插在 `Switch-B`**（无链路聚合）**。`Switch-A` 和 `Switch-B` 之间的堆叠线缆（或互联链路）断了。

`Switch-A` 到核心路由器的上行链路**正常**。`Switch-B` 到核心路由器的上行链路也**正常**。



`Master` 和 `Backup` 之间的网络（通常是 VRRP 心跳走的网络）中断了。

- `Backup` 收不到 `Master` 的心跳，认为 `Master` 已死，于是**它接管了 VIP**。
- `Master` 发现自己联系不上 `Backup`，但它仍然认为自己是 `Master`（因为它优先级高），于是**它继续持有 VIP**。



网络上同时出现了两台服务器都声称自己拥有同一个 VIP（`192.168.1.100`）。这会导致严重的 IP 地址冲突。

- 上游交换机的 MAC 地址表会因为这个 VIP 对应的 MAC 地址在两个不同端口（一个连 `Master`，一个连 `Backup`）之间疯狂“漂移”(MAC Flapping)。
- 导致客户端的流量时而被发到 `Master`，时而被发到 `Backup`，表现为服务极不稳定、时断时续。





### 应用层单点故障

**数据库单点故障**：两台 NGINX 后有多台 WEB 应用服务器处理流量，WEB 应用需要用到数据库，如果这一个数据库出现故障，整个 WEB 服务不可用。

**共享存储**：如果 NGINX 用于提供静态文件，而这些文件存储在一个**单点**的 NFS 或 CIFS 挂载上。如果这个存储服务宕机，NGINX 会返回 **404**。

**SSL 证书**：两个 NGINX 节点上的 SSL 证书依赖一个自动化服务（例如 Certbot、acme.sh 等）来续期证书。如果自动化续期服务本身的配置文件写错了（比如 API 密钥错误、域名列表错误），或者 DNS 服务商的 API 出现故障或服务中断，导致 `dns-01` 挑战无法完成（无法添加或验证 TXT 记录）。会导致两个 NGINX 节点上的 SSL 证书同时过期。尽管 NGINX 服务（`service is "Up"`）本身在运行，但所有客户端浏览器都会显示严重的安全警告，导致用户无法访问服务，服务事实性中断。



## 主备模式示例

Keepalived + VRRP 主备模式这是一个非常经典且实用的高可用（HA）架构。

Keepalived 利用 VRRP (Virtual Router Redundancy Protocol) 协议，允许两台或多台服务器共享一个虚拟 IP 地址（VIP）。

在主备模式下，只有一台服务器（MASTER）会持有这个 VIP 并对外提供服务，另一台（BACKUP）则处于待命状态，持续监控 MASTER。当 MASTER 发生故障时，BACKUP 会自动接管 VIP，从而实现服务的快速切换，保证业务连续性。



### 实验环境

**服务器 A (主 - MASTER):**

- 主机名: `NGINX-A`
- 物理网卡：`eth0`
- 物理 IP: `192.168.1.101`

**服务器 B (备 - BACKUP):**

- 主机名: `NGINX-B`
- 物理 IP: `192.168.1.102`
- 操作系统: Linux (同上)



`192.168.1.100` (VIP) 默认在 `NGINX-A` 上。当 `NGINX-A` 宕机或 Keepalived 服务停止时，`192.168.1.100` 自动漂移到 `NGINX-B` 上。当 `NGINX-A` 恢复后，VIP 会自动漂移回 `NGINX-B` (这是默认的抢占模式)。



### 网络配置

#### NGINX-A

在 NGINX-A 上，使用 `vim` 编辑 `/etc/network/interfaces` 文件，为 eth0 网卡配置静态 IP。

```
vim /etc/network/interfaces
```

写入配置文件，将其 IP 地址设为 `192.168.1.101/24` 并设置为自动启动。

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
	address 192.168.1.101/24
```



使用 `ifdown` 和 `ifup` 命令重启 eth0 网卡，使新的 IP 地址 `192.168.1.101` 生效。

```
ifdown eth0 && ifup eth0
```



#### NGINX-B

在 NGINX-B 上，同样编辑 `/etc/network/interfaces` 文件，为 eth0 配置 IP 地址。

```
vim /etc/network/interfaces
```

写入配置文件，将其 IP 地址设为 `192.168.1.102/24`。

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
	address 192.168.1.102/24
```



重启 NGINX-B 的 eth0 网卡，使 `192.168.1.102` 这个 IP 配置生效。

```
ifdown eth0 && ifup eth0
```



在 NGINX-A 上 `ping` NGINX-B 的 IP，以测试两台服务器的网络是否连通。

```
ping 192.168.1.102 -c 3 
```

```
NGINX-A:~# ping 192.168.1.102 -c 3 
PING 192.168.1.102 (192.168.1.102): 56 data bytes
64 bytes from 192.168.1.102: seq=0 ttl=64 time=0.305 ms
64 bytes from 192.168.1.102: seq=1 ttl=64 time=0.277 ms
64 bytes from 192.168.1.102: seq=2 ttl=64 time=0.216 ms

--- 192.168.1.102 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.216/0.266/0.305 ms
```



### 防火墙配置

VRRP 是一种网络层（IP 层）协议，它不使用 TCP 或 UDP 端口，而是使用自己的 **IP 协议号（112）**。

在 Alpine Linux 操作系统中，默认不存在防火墙规则，下面介绍如何使用 iptables 放行 VRRP 协议流量。



**允许 VRRP 协议 (协议号 112)：** 在 iptables 的 INPUT 链顶部插入规则，使用 `-p vrrp` 按协议名称允许所有入站 VRRP 流量。

```
iptables -I INPUT -p vrrp -j ACCEPT
```

或者，使用 `-p 112` 按 IP 协议号 112 来允许 VRRP 流量，效果与上一条相同。

```
iptables -I INPUT -p 112 -j ACCEPT
```



如果 VRRP 配置（例如在 `keepalived.conf` 中）启用了认证（`auth_type AH`），那么您**还必须**允许 **AH (Authentication Header)** 协议。

**允许 AH 协议 (协议号 51)：** 这条规则允许所有传入的 AH 流量。

```
iptables -I INPUT -p ah -j ACCEPT
```

使用 `-p 51` 按协议号 51 放行 AH 协议，与上一条命令效果相同。

```
iptables -I INPUT -p 51 -j ACCEPT
```



注意：防火墙配置因网络环境而异，请根据您服务器的实际情况自行检查并设置。



### NGINX 服务部署

#### NGINX-A

在 NGINX-A 上，使用 `apk` 安装 NGINX，然后立即启动服务并将其设置为开机自启。

```
apk add nginx
rc-service nginx start
rc-update add nginx default
```



删除 NGINX 自带的默认配置文件。

```
rm -f /etc/nginx/http.d/default.conf
```



在 `http.d` 目录中创建 `static.conf` 文件，NGINX 会自动加载此目录下的配置。

```
vim /etc/nginx/http.d/static.conf
```

写入 `server` 配置块，使其监听 80 端口，并将网站根目录 `root` 指向 `/var/www/html`。

```
server {
    listen 80 default_server;

    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    error_page 404 /404.html;
}
```



创建 `/var/www/html` 目录，这个目录将存放 NGINX 服务的网页文件。

```
mkdir /var/www/html/
```



创建 `index.html` 首页文件，并使用 `echo` 命令写入 "nginx-1" 作为网页内容。

```
touch /var/www/html/index.html
echo "nginx-1" > /var/www/html/index.html
```



使用 `chown` 和 `chmod` 更改 `/var/www/html` 目录的所有权和权限，确保 nginx 用户可读。

```
chown nginx:nginx /var/www/html/
chmod 755 /var/www/html/
```



执行 `nginx -t` 命令来测试所有 NGINX 配置文件的语法是否正确，防止加载错误。

```
nginx -t 
```

```
# nginx -t 
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```



使用 `rc-service nginx reload` 命令平滑地重新加载 NGINX，应用新的 `static.conf` 配置。

```
rc-service nginx reload
```



在本地使用 `curl` 访问 `127.0.0.1`，测试 NGINX 服务是否已在 80 端口正常工作。

```
# curl http://127.0.0.1
nginx-1
```



#### NGINX-B

配置步骤与 **NGINX-A** 相同，将 **/var/www/html/index.html** 文件的内容设置为 **nginx-2**。

```
echo "nginx-2" > /var/www/html/index.html
```



在本地使用 `curl` 访问 `127.0.0.1`，测试 NGINX 服务是否已在 80 端口正常工作。

```
# curl http://127.0.0.1
nginx-2
```

**注意：请检查返回的内容是否为 `nginx-2`。**



### Keepalived 部署

#### NGINX-A

在 NGINX-A（主节点）上，使用 `apk` 包管理器安装 Keepalived，并将其设置为开机自启动。

```
apk add keepalived
rc-update add keepalived default
```



为 Keepalived 创建一个专门存放配置文件的目录 `/etc/keepalived/`。

```
mkdir /etc/keepalived/
```



使用 `vim` 编辑器创建并打开 NGINX-A 的 Keepalived 核心配置文件。

```
vim /etc/keepalived/keepalived.conf
```

写入 NGINX-A（主节点）的配置：设置 `router_id`（应唯一，示例中为 NGINX-A），定义 NGINX 健康检查脚本 `chk_nginx`，并将 `vrrp_instance` 状态设为 `MASTER`，优先级 `priority` 设为 100。

```
global_defs {
    router_id NGINX-A   # 主节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -20              # 失败时降低优先级 20
}

vrrp_instance VI_1 {
    state MASTER            # 主节点状态
    interface eth0          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（两节点一致）
    priority 100            # 优先级（主节点较高）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（两节点一致）
    }
    virtual_ipaddress {
        192.168.1.100/24     # 虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}

```



配置完成后，在 NGINX-A 上启动 Keepalived 服务，使其开始作为主节点工作。

```
rc-service keepalived start
```



#### NGINX-B

在 NGINX-B（备用节点）上，同样安装 Keepalived 软件包并设置开机自启。

```
apk add keepalived
rc-update add keepalived default
```



在 NGINX-B 上也创建 `/etc/keepalived/` 配置目录。

```
mkdir /etc/keepalived/
```



使用 `vim` 编辑器创建 NGINX-B 的 Keepalived 配置文件。

```
vim /etc/keepalived/keepalived.conf
```



写入 NGINX-B（备用节点）的配置：`router_id` 必须唯一（示例中为 NGINX-B），`priority` 设为 90（低于主节点），而 `virtual_router_id`、`auth_pass` 和 `virtual_ipaddress` 必须与 NGINX-A 完全一致。

```
global_defs {
    router_id NGINX-B   # 主节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -20              # 失败时降低优先级 20
}

vrrp_instance VI_1 {
    state MASTER            # 主节点状态
    interface eth0          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（两节点一致）
    priority 90            # 优先级（主节点较高）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（两节点一致）
    }
    virtual_ipaddress {
        192.168.1.100/24     # 虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}

```



在 NGINX-B 上启动 Keepalived 服务，它将与 NGINX-A 协商，因优先级较低而成为备用节点。

```
rc-service keepalived start
```



### 测试

在两台服务器的 Keepalived 都正常运行时，使用 `curl` 访问 `192.168.1.100` 这个虚拟 IP (VIP)。预期会看到 "nginx-1"，表明请求正由主节点 NGINX-A 处理。

```
# curl http://192.168.1.100 
nginx-1
```



在 NGINX-A（主节点）上手动停止 NGINX 服务。这将触发 `chk_nginx` 健康检查脚本失败，导致 Keepalived 降低 NGINX-A 的优先级。

```
rc-service nginx stop
```



在 NGINX-A 故障后，再次访问虚拟 IP `192.168.1.100`。预期会看到 "nginx-2"，表明 Keepalived 已将 VIP 自动漂移到备用节点 NGINX-B。

```
# curl http://192.168.1.100 
nginx-2
```





## 主主模式示例

Keepalived + VRRP 主主模式（Active-Active）是一种高效的高可用（HA）架构。

与主备模式不同，主主模式允许两台服务器同时处于活动状态，各自持有一个虚拟 IP 地址（VIP），并互为备份。

在此示例中，服务器 A（`NGINX-A`）将主要持有 `VIP1`，服务器 B（`NGINX-B`）将主要持有 `VIP2`。它们会持续互相监控。

- 当 `NGINX-A` 发生故障时，`NGINX-B` 会自动接管 `VIP1`（此时 `NGINX-B` 持有两个 VIP）。
- 当 `NGINX-B` 发生故障时，`NGINX-A` 会自动接管 `VIP2`（此时 `NGINX-A` 持有两个 VIP）。

此外，我们将引入一台 `GATEWAY` 服务器，它将作为流量入口，使用 `iptables` 将访问其公网 IP（`1.1.1.1`）的请求，负载均衡到 `VIP1` 和 `VIP2` 上，从而实现两台 NGINX 服务器同时对外提供服务。



### 实验环境

**服务器 A (主 - MASTER):**

- 主机名: `NGINX-A`
- 物理网卡：`eth0`
- 物理 IP: `192.168.1.101`

**服务器 B (备 - BACKUP):**

- 主机名: `NGINX-B`
- 物理 IP: `192.168.1.102`
- 操作系统: Linux (同上)

**网关服务器 (GATEWAY):**

- 主机名: `GATEWAY`
- 网卡: `eth0`
- 内网 IP: `192.168.1.1`
- "公网" IP: `1.1.1.1/32` (配置在 eth0 上)
- 操作系统: Linux (同上)

**虚拟 IP (VIPs):**

- `192.168.1.100` (VIP1) 默认在 `NGINX-A` 上。
- `192.168.1.200` (VIP2) 默认在 `NGINX-B` 上。





### 网络配置

#### NGINX-A

在 NGINX-A 上，使用 `vim` 编辑 `/etc/network/interfaces` 文件，为 eth0 网卡配置静态 IP。

```
vim /etc/network/interfaces
```

写入配置文件，将其 IP 地址设为 `192.168.1.101/24` 并设置为自动启动。

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
	address 192.168.1.101/24
```



使用 `ifdown` 和 `ifup` 命令重启 eth0 网卡，使新的 IP 地址 `192.168.1.101` 生效。

```
ifdown eth0 && ifup eth0
```



#### NGINX-B

在 NGINX-B 上，同样编辑 `/etc/network/interfaces` 文件，为 eth0 配置 IP 地址。

```
vim /etc/network/interfaces
```

写入配置文件，将其 IP 地址设为 `192.168.1.102/24`。

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
	address 192.168.1.102/24
```



重启 NGINX-B 的 eth0 网卡，使 `192.168.1.102` 这个 IP 配置生效。

```
ifdown eth0 && ifup eth0
```



#### GATEWAY

在 GATEWAY 上，编辑 `/etc/network/interfaces` 文件，为 `eth0` 配置 `192.168.1.1/24` 和 `1.1.1.1/32` 两个 IP 地址。

```
vim /etc/network/interfaces
```

写入配置文件：

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.1.1/24
    address 1.1.1.1/32
```



重启网卡使配置生效：

```
ifdown eth0 && ifup eth0 && ifdown eth1 && ifup eth1
```



#### 连通性测试

在 NGINX-A 上 `ping` NGINX-B 的 IP，以测试两台服务器的网络是否连通。

```
ping 192.168.1.102 -c 3 
```

```
NGINX-A:~# ping 192.168.1.102 -c 3 
PING 192.168.1.102 (192.168.1.102): 56 data bytes
64 bytes from 192.168.1.102: seq=0 ttl=64 time=0.305 ms
64 bytes from 192.168.1.102: seq=1 ttl=64 time=0.277 ms
64 bytes from 192.168.1.102: seq=2 ttl=64 time=0.216 ms

--- 192.168.1.102 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.216/0.266/0.305 ms
```



### 防火墙配置

VRRP 是一种网络层（IP 层）协议，它不使用 TCP 或 UDP 端口，而是使用自己的 **IP 协议号（112）**。

在 Alpine Linux 操作系统中，默认不存在防火墙规则，下面介绍如何使用 iptables 放行 VRRP 协议流量。



**允许 VRRP 协议 (协议号 112)：** 在 iptables 的 INPUT 链顶部插入规则，使用 `-p vrrp` 按协议名称允许所有入站 VRRP 流量。

```
iptables -I INPUT -p vrrp -j ACCEPT
```

或者，使用 `-p 112` 按 IP 协议号 112 来允许 VRRP 流量，效果与上一条相同。

```
iptables -I INPUT -p 112 -j ACCEPT
```



如果 VRRP 配置（例如在 `keepalived.conf` 中）启用了认证（`auth_type AH`），那么您**还必须**允许 **AH (Authentication Header)** 协议。

**允许 AH 协议 (协议号 51)：** 这条规则允许所有传入的 AH 流量。

```
iptables -I INPUT -p ah -j ACCEPT
```

使用 `-p 51` 按协议号 51 放行 AH 协议，与上一条命令效果相同。

```
iptables -I INPUT -p 51 -j ACCEPT
```



注意：防火墙配置因网络环境而异，请根据您服务器的实际情况自行检查并设置。



### NGINX 服务部署

#### NGINX-A

在 NGINX-A 上，使用 `apk` 安装 NGINX，然后立即启动服务并将其设置为开机自启。

```
apk add nginx
rc-service nginx start
rc-update add nginx default
```



删除 NGINX 自带的默认配置文件。

```
rm -f /etc/nginx/http.d/default.conf
```



在 `http.d` 目录中创建 `static.conf` 文件，NGINX 会自动加载此目录下的配置。

```
vim /etc/nginx/http.d/static.conf
```

写入 `server` 配置块，使其监听 80 端口，并将网站根目录 `root` 指向 `/var/www/html`。

```
server {
    listen 80 default_server;

    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    error_page 404 /404.html;
}
```



创建 `/var/www/html` 目录，这个目录将存放 NGINX 服务的网页文件。

```
mkdir /var/www/html/
```



创建 `index.html` 首页文件，并使用 `echo` 命令写入 "nginx-1" 作为网页内容。

```
touch /var/www/html/index.html
echo "nginx-1" > /var/www/html/index.html
```



使用 `chown` 和 `chmod` 更改 `/var/www/html` 目录的所有权和权限，确保 nginx 用户可读。

```
chown nginx:nginx /var/www/html/
chmod 755 /var/www/html/
```



执行 `nginx -t` 命令来测试所有 NGINX 配置文件的语法是否正确，防止加载错误。

```
nginx -t 
```

```
# nginx -t 
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```



使用 `rc-service nginx reload` 命令平滑地重新加载 NGINX，应用新的 `static.conf` 配置。

```
rc-service nginx reload
```



在本地使用 `curl` 访问 `127.0.0.1`，测试 NGINX 服务是否已在 80 端口正常工作。

```
# curl http://127.0.0.1
nginx-1
```



#### NGINX-B

配置步骤与 **NGINX-A** 相同，将 **/var/www/html/index.html** 文件的内容设置为 **nginx-2**。

```
echo "nginx-2" > /var/www/html/index.html
```



在本地使用 `curl` 访问 `127.0.0.1`，测试 NGINX 服务是否已在 80 端口正常工作。

```
# curl http://127.0.0.1
nginx-2
```

**注意：请检查返回的内容是否为 `nginx-2`。**



### Keepalived 部署

#### NGINX-A

在 NGINX-A（主节点）上，使用 `apk` 包管理器安装 Keepalived，并将其设置为开机自启动。

```
apk add keepalived
rc-update add keepalived default
```



为 Keepalived 创建一个专门存放配置文件的目录 `/etc/keepalived/`。

```
mkdir /etc/keepalived/
```



使用 `vim` 编辑器创建并打开 NGINX-A 的 Keepalived 核心配置文件。

```
vim /etc/keepalived/keepalived.conf
```

写入 NGINX-A（主主）的配置：

- `VI_1` (VIP1): 状态为 `MASTER`，优先级 `100`。
- `VI_2` (VIP2): 状态为 `BACKUP`，优先级 `90`。

```
global_defs {
    router_id NGINX-A   # 主节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2              # 检查间隔 2 秒
    weight -20              # 失败时降低优先级 20
}

# VIP1 (192.168.1.100) 的实例, NGINX-A 是 MASTER
vrrp_instance VI_1 {
    state MASTER            # 主节点状态
    interface eth0          # 网卡名称
    virtual_router_id 51    # 虚拟路由器 ID（两节点一致）
    priority 100            # 优先级（主节点较高）
    advert_int 1            # VRRP 公告间隔（秒）
    authentication {
        auth_type PASS      # 认证类型
        auth_pass mysecret  # 认证密码（两节点一致）
    }
    virtual_ipaddress {
        192.168.1.100/24     # 虚拟 IP
    }
    track_script {
        chk_nginx          # 关联健康检查脚本
    }
}

# VIP2 (192.168.1.200) 的实例, NGINX-A 是 BACKUP
vrrp_instance VI_2 {
    state BACKUP            # 备用节点状态
    interface eth0
    virtual_router_id 52    # 虚拟路由器 ID (VI_2 组内一致)
    priority 90             # 优先级（BACKUP 较低）
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass mysecret  # 认证密码（所有节点一致）
    }
    virtual_ipaddress {
        192.168.1.200/24    # 虚拟 IP 2
    }
    track_script {
        chk_nginx
    }
}
```



配置完成后，在 NGINX-A 上启动 Keepalived 服务，使其开始作为主节点工作。

```
rc-service keepalived start
```



#### NGINX-B

在 NGINX-B（备用节点）上，同样安装 Keepalived 软件包并设置开机自启。

```
apk add keepalived
rc-update add keepalived default
```



在 NGINX-B 上也创建 `/etc/keepalived/` 配置目录。

```
mkdir /etc/keepalived/
```



使用 `vim` 编辑器创建 NGINX-B 的 Keepalived 配置文件。

```
vim /etc/keepalived/keepalived.conf
```

写入 NGINX-B（主主）的配置（与 NGINX-A **相反**）：

- `VI_1` (VIP1): 状态为 `BACKUP`，优先级 `90`。
- `VI_2` (VIP2): 状态为 `MASTER`，优先级 `100`。

```
global_defs {
    router_id NGINX-B   # 节点唯一标识
}

vrrp_script chk_nginx {
    script "pidof nginx"    # 检查 Nginx 是否运行
    interval 2
    weight -20
}

# VIP1 (192.168.1.100) 的实例, NGINX-B 是 BACKUP
vrrp_instance VI_1 {
    state BACKUP            # 备用节点状态
    interface eth0
    virtual_router_id 51    # 必须与 NGINX-A 的 VI_1 一致
    priority 90             # 优先级（BACKUP 较低）
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass mysecret
    }
    virtual_ipaddress {
        192.168.1.100/24
    }
    track_script {
        chk_nginx
    }
}

# VIP2 (192.168.1.200) 的实例, NGINX-B 是 MASTER
vrrp_instance VI_2 {
    state MASTER            # 主节点状态
    interface eth0
    virtual_router_id 52    # 必须与 NGINX-A 的 VI_2 一致
    priority 100            # 优先级（MASTER 较高）
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass mysecret
    }
    virtual_ipaddress {
        192.168.1.200/24
    }
    track_script {
        chk_nginx
    }
}
```



在 NGINX-B 上启动 Keepalived 服务，它将与 NGINX-A 协商，因优先级较低而成为备用节点。

```
rc-service keepalived start
```



### 网关负载均衡配置

使用 `apk` 安装 `iptables` 软件包，并使用 `rc-update` 将其服务设置为开机自启动。

```
apk add iptables
rc-update add iptables default
```



使用 `vim` 编辑器打开 `iptables` 服务的配置文件，以修改其默认行为。

```
vim /etc/conf.d/iptables
```



在配置文件中，将 `SAVE_ON_STOP` 改为 `no`（避免意外覆盖规则），并将 `IPFORWARD` 改为 `yes`（开启内核的 IP 转发功能）。

```diff
     1	# /etc/conf.d/iptables
     2	
     3	# Location in which iptables initscript will save set rules on 
     4	# service shutdown
     5	IPTABLES_SAVE="/etc/iptables/rules-save"
     6	
     7	# Options to pass to iptables-save and iptables-restore 
     8	SAVE_RESTORE_OPTIONS="-c"
     9	
    10 # Save state on stopping iptables
-   11 SAVE_ON_STOP="yes"
+   11 SAVE_ON_STOP="no"
    12 
    13 # Enable/disable IPv4 forwarding with the rules
-   14 IPFORWARD="no"
+   14 IPFORWARD="yes"
```



添加 `PREROUTING` 规则，将从 `eth1` 传入的新 80 端口 TCP 连接 50% 随机 DNAT 到 NGINX-A (192.168.1.100)，剩下 50% 到 NGINX-B (192.168.1.200)。

```
# 50% 的新连接到 NGINX-A
iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -m conntrack --ctstate NEW -m statistic --mode random --probability 0.5 -j DNAT --to-destination 192.168.1.100:80

# 剩下 50% 的新连接到 NGINX-B
iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -m conntrack --ctstate NEW -j DNAT --to-destination 192.168.1.200:80
```



添加 `OUTPUT` 规则，将网关本机发往 `1.1.1.1` 的新 80 端口连接 50/50 随机 DNAT 到 NGINX-A 和 NGINX-B。

```
# 本机 50% 的新连接到 NGINX-A
iptables -t nat -A OUTPUT -d 1.1.1.1 -p tcp --dport 80 -m conntrack --ctstate NEW -m statistic --mode random --probability 0.5 -j DNAT --to-destination 192.168.1.100:80

# 本机剩下 50% 的新连接到 NGINX-B
iptables -t nat -A OUTPUT -d 1.1.1.1 -p tcp --dport 80 -m conntrack --ctstate NEW -j DNAT --to-destination 192.168.1.200:80
```



本机进程（例如 `curl http://1.1.1.1`）生成数据包时，Linux 内核会*在*数据包进入 `iptables OUTPUT` 链*之前*进行一次路由决策，以确定数据包的出口接口。由于 `1.1.1.1` 配置在本地（如 `eth0`），内核会通过 `local` 路由表（`ip route show table local`）匹配到一条高优先级的 `local 1.1.1.1 ... scope host` 路由，并*预先决定*数据包的出口是 `lo`（环回接口）。

数据包随后进入 `OUTPUT` 链，被 DNAT 规则正确修改目标地址（例如变为 `192.168.1.100`）。但问题是，数据包的出口接口已经被锁定为 `lo`，因此这个目标为 `192.168.1.100` 的数据包被错误地从 `lo` 接口发送，无法到达目标 NGINX 主机。`ip route del local 1.1.1.1 table local` 命令就是为了删除这条导致问题的高优先级 `local` 路由。接着，`ip route add 1.1.1.1 dev eth0 scope link proto static` 添加了一条新规则，将 `1.1.1.1` 视为一个普通的、通过 `eth0` 链路可达的 IP。这样，路由决策就会选择 `eth0` 为出口，数据包在 `OUTPUT` 链被 DNAT 后，就能被正确地从 `eth0` 接口发送出去。

```
ip route del local 1.1.1.1 table local
ip route add 1.1.1.1 dev eth0 scope link proto static
```



执行 `save` 命令，将当前内存中的 `iptables` 规则保存到 `/etc/iptables/rules-save` 文件中，使其持久化。

```
rc-service iptables save
```



启动 `iptables` 服务，这将从保存的规则文件中加载配置并使其生效。

```
rc-service iptables start
```



### 测试

在主主（Active-Active）模式正常运行时，连续 `curl` 访问 `1.1.1.1` 十次。返回结果中混合了 "nginx-1" 和 "nginx-2"，表明两个节点都在处理请求。

```
for i in $(seq 1 10); do curl http://1.1.1.1; done
```

```
# for i in $(seq 1 10); do curl http://1.1.1.1; done 
nginx-2
nginx-2
nginx-1
nginx-1
nginx-1
nginx-2
nginx-2
nginx-2
nginx-1
nginx-1
```



在 `NGINX-A`（主节点）上手动停止 NGINX 服务，模拟 `NGINX-A` 发生故障。

```
rc-service nginx stop
```



再次执行 `curl` 循环。所有十次请求均返回 "nginx-2"，表明所有流量已自动切换到 `NGINX-B` 节点。

```
for i in $(seq 1 10); do curl http://1.1.1.1; done
```

```
# for i in $(seq 1 10); do curl http://1.1.1.1; done
nginx-2
nginx-2
nginx-2
nginx-2
nginx-2
nginx-2
nginx-2
nginx-2
nginx-2
nginx-2
```



开启 `NGINX-A` 节点上的 NGINX 服务，模拟 `NGINX-A` 故障恢复。

```
rc-service nginx start
```



再次连续访问 `1.1.1.1`。返回结果再次变为 "nginx-1" 和 "nginx-2" 的混合，表明 `NGINX-A` 已重新加入集群并开始处理流量。

```
for i in $(seq 1 10); do curl http://1.1.1.1; done
```

```
# for i in $(seq 1 10); do curl http://1.1.1.1; done
nginx-1
nginx-2
nginx-2
nginx-2
nginx-2
nginx-1
nginx-2
nginx-2
nginx-2
nginx-1
```



在 `NGINX-B` 节点上停止 NGINX 服务，模拟 `NGINX-B` 发生故障。

```
rc-service nginx stop
```



连续访问 `1.1.1.1`。现在所有请求均返回 "nginx-1"，表明流量已全部切换到 `NGINX-A` 节点。

```
for i in $(seq 1 10); do curl http://1.1.1.1; done
```

```
# for i in $(seq 1 10); do curl http://1.1.1.1; done 
nginx-1
nginx-1
nginx-1
nginx-1
nginx-1
nginx-1
nginx-1
nginx-1
nginx-1
nginx-1
```



开启 `NGINX-B` 节点上的 NGINX 服务，模拟 `NGINX-B` 故障恢复。

```
rc-service nginx start
```



最后再次执行 `curl` 循环。返回结果恢复为 "nginx-1" 和 "nginx-2" 混合，证明 `NGINX-B` 已成功恢复并重新开始处理流量。

```
for i in $(seq 1 10); do curl http://1.1.1.1; done
```

```
# for i in $(seq 1 10); do curl http://1.1.1.1; done
nginx-1
nginx-2
nginx-1
nginx-2
nginx-2
nginx-1
nginx-1
nginx-2
nginx-1
nginx-1
```

