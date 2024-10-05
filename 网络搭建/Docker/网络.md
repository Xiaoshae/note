# Docker Network

**docker network** 命令用于**管理 Docker 网络**。这些命令可以**创建、列出、删除和检查**网络，帮助用户在 Docker 容器之间建立通信。

常用 docker network 命令：

- **ls**：列出所有网络
- **inspect**：查看网络详细信息
- **create**：创建一个新网络
- **rm**：删除一个或多个网络
- **connect**：将一个容器连接到一个网络
- **disconnect**：将一个容器从一个网络断开





**docker network ls** 命令

列出所有网络。

输出：

```
NETWORK ID          NAME                DRIVER              SCOPE
b649b57f5bc5        bridge              bridge              local
7e8c2d2c0b5a        host                host                local
6a9c8d69bfb2        none                null                local
```



**docker network inspect** 命令

查看指定网络的详细信息。

输出：

```
[
    {
        "Name": "my_network",
        "Id": "b649b57f5bc5",
        "Created": "2024-07-23T00:00:00.000000000Z",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
                    "Subnet": "172.18.0.0/16",
                    "Gateway": "172.18.0.1"
                }
            ]
        },
        "Internal": false,
        "Attachable": false,
        "Containers": {},
        "Options": {},
        "Labels": {}
    }
]
```





**docker network rm** 命令

删除一个网络。

```
docker network rm my_network
```

删除多个网络：

```
docker network rm network1 network2
```



**docker network connect** 命令

将一个容器连接到一个网络。

```
docker network connect my_network my_container
```



**docker network disconnect** 命令

将一个容器从一个网络断开。

```
docker network disconnect my_network my_container
```



## Docker 网络类型

## none

如果你想完全隔离容器的网络堆栈，可以`--network none`在启动容器时使用该标志。在容器内，仅创建环回设备。



以下示例显示了使用网络驱动程序在容器`ip link show`中的输出。`alpine` `none`

```console
$ docker run --rm --network none alpine:latest ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```



没有为使用该驱动程序的容器配置 IPv6 环回地址`none`。

```console
$ docker run --rm --network none --name no-net-alpine alpine:latest ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
```



## host

如果您为容器使用 `host` 网络模式，该容器的网络堆栈不会与 Docker 主机隔离（容器共享主机的网络命名空间），并且容器不会分配到自己的 IP 地址。例如，如果您运行一个绑定到端口 80 的容器，并且使用 `host` 网络模式，则该容器的应用程序可在主机 IP 地址的端口 80 上使用。



**注意**：host 鉴于使用模式网络时**容器没有自己的 IP 地址** ，**端口映射不会生效**，并且-p、--publish、-P和--publish-all选项将被忽略，而是产生警告：

```
WARNING: Published ports are discarded when using host network mode
```





## bridge

当您启动 Docker 时，会自动创建一个默认的 Bridge 网络（也称为 `bridge` ），除非另有指定，否则新启动的容器将连接到该网络。您也可以创建用户定义的自定义 Bridge 网络。用户定义的 Bridge 网络优于默认的 `bridge` 网络。

在 Docker 方面，桥接网络使用软件桥接，使连接到同一桥接网络的容器能够相互通信，同时与未连接到该桥接网络的容器隔离。Docker 桥接驱动程序会自动在主机上安装规则，以防止不同桥接网络上的容器直接通信。



用户定义的 Bridge 与默认 Bridge 的区别

- 所有未指定 `--network` 的容器都连接到默认的桥接网络。
- 用户定义的网桥在容器之间提供自动 DNS 解析。
- 在默认网桥网络上的容器只能通过 IP 地址访问彼此，除非您使用 `--link` 选项，这被认为是遗留选项。在用户定义的网桥网络上，容器可以通过名称或别名解析彼此。
- 容器可以随时连接和断开与用户定义的网络的连接，从默认的桥接网络中移除，需要停止该容器并使用不同的网络选项重新创建它。
- 在默认桥接网络上**链接的容器**共享环境变量。
- 连接到相同用户定义桥接网络的容器实际上将所有端口互相暴露。若要使不同网络上的容器或非 Docker 主机能够访问某个端口，必须使用 `-p` 或 `--publish` 标志发布该端口。



**docker network create** 命令

```
docker network create my_network
```

**常用参数**：

- **`--driver`**: 指定网络驱动程序（如 `bridge`、`host`、`overlay`）。
- **`--subnet`**: 指定子网。
- **`--gateway`**: 指定网关。
- **`--ip-range`**: 指定可用 IP 地址范围。
- **`--ipv6`**: 启用 IPv6。
- **`--label`**: 为网络添加标签。



示例：

```
docker network create \
	--driver bridge \
	--subnet 192.168.1.0/24 \
	--ip-range 192.168.1.0/28 \
	--gateway 192.168.1.1 \
	--ipv6 \
	--subnet=2001:db8:abc8::/64 \
    --gateway=2001:db8:abc8::10 \
	my_network
```



## ipvlan

IPvlan 是一种对经过验证的网络虚拟化技术的新改进。Linux 实现极其轻量级，因为它们不是使用传统的 Linux 桥接进行隔离，而是关联到一个 Linux 以太网接口或子接口以强制执行网络之间的分离和与物理网络的连接。







## macvlan

某些应用程序，特别是遗留应用程序或监视网络流量的应用程序，期望直接连接到物理网络。在这种情况下，您可以使用 `macvlan` 网络驱动程序为每个容器的虚拟网络接口分配一个 MAC 地址，使其看起来像是直接连接到物理网络的物理网络接口。在这种情况下，您需要指定 Docker 主机上的物理接口以供 Macvlan 使用，以及网络的子网和网关。您甚至可以使用不同的物理网络接口隔离您的 Macvlan 网络。



请记住以下事项：

- 您可能会因为 IP 地址耗尽或“VLAN 扩散”而无意中降低网络性能，大量的不同MAC地址充斥在局域网（LAN）内，导致了不必要的广播流量增加，或者交换机的MAC地址表过载，从而影响了网络的性能。
- 您的网络设备需要能够处理“混杂模式”，在这种模式下，一个物理接口可以分配多个 MAC 地址。
- 如果您的应用程序可以使用桥接（在单个 Docker 主机上）或覆盖网络（在多个 Docker 主机之间通信），这些解决方案可能从长远来看更好。



### Options

| Option         | 默认     | 描述                                                         |
| :------------- | :------- | :----------------------------------------------------------- |
| `macvlan_mode` | `bridge` | 可以是以下之一： `bridge` ， `vepa` ， `passthru` ， `private` |
| `parent`       |          | 指定要使用的父接口。                                         |



### 创建一个 Macvlan 网络

当您创建一个 Macvlan 网络时，它可以是桥接模式或 802.1Q Trunk 桥接模式。

- 在桥接模式下，Macvlan 流量通过主机上的一个物理设备传输。
- 在 802.1Q Trunk 桥接模式下，流量通过 Docker 动态创建的 802.1Q 子接口传输。这允许您在更细粒度的级别上控制路由和过滤。



要创建一个 `macvlan` 网络，该网络与给定的物理网络接口桥接，请使用 `--driver macvlan` 和 `docker network create` 命令。您还需要指定 `parent` ，这是 Docker 主机上流量将实际通过的接口。

```
 docker network create -d macvlan \
  --subnet=172.16.86.0/24 \
  --gateway=172.16.86.1 \
  -o parent=eth0 pub_net
```



如果需要从 `macvlan` 网络中排除 IP 地址，例如某个 IP 地址已在使用，则使用 `--aux-addresses` ：

```console
docker network create -d macvlan \
  --subnet=192.168.32.0/24 \
  --ip-range=192.168.32.128/25 \
  --gateway=192.168.32.254 \
  --aux-address="my-router=192.168.32.129" \
  -o parent=eth0 macnet32
```





### 指定IP地址范围

Docker容器不会使用交换机（或路由器）的DHCP分配地址，而是会使用其子网中可用的最低主机位来分配IP地址，这样可能会导致Docker分配的IP地址，已经在这个网络中存在（被交换机或路由器的DHCP服务分配给了其他设备）。

可用通过--ip-range来限制Docker可分配的IP地址范围。

```
 docker network create -d macvlan \
  --subnet=172.16.86.0/24 \
  --ip-range=192.168.86.253/32 \
  --gateway=172.16.86.1 \
  -o parent=eth0 pub_net
```



如果--ip-range指定的IP地址范围被分配完毕，则在此使用该网络创建容器时会失败。

可用在docker run创建容器时，使用 --ip 选项来给容器指定IP地址。

```
docker run --rm -d --ip 192.168.86.25 --network custom centos:latest
```





### 802.1Q 干道桥模式

如果你指定了一个包含点的 `parent` 接口名称，例如 `eth0.50` ，Docker 会将其解释为 `eth0` 的子接口，并自动创建子接口。

```
docker network create -d macvlan \
    --subnet=192.168.50.0/24 \
    --gateway=192.168.50.1 \
    -o parent=eth0.50 macvlan50
```



### 使用 IPvlan 而不是 Macvlan

在上面的例子中，你仍然在使用一个 L3 桥接。你可以使用 `ipvlan` ，以获得一个 L2 桥接。指定 `-o ipvlan_mode=l2` 。

```console
docker network create -d ipvlan \
    --subnet=192.168.210.0/24 \
    --subnet=192.168.212.0/24 \
    --gateway=192.168.210.254 \
    --gateway=192.168.212.254 \
     -o ipvlan_mode=l2 -o parent=eth0 ipvlan210
```



### Use IPv6 使用 IPv6

如果您已将 Docker 守护程序配置为允许 IPv6，则可以使用双栈 IPv4/IPv6 `macvlan` 网络。

```console
 docker network create -d macvlan \
    --subnet=192.168.216.0/24 \
    --subnet=192.168.218.0/24 \
    --gateway=192.168.216.1 \
    --gateway=192.168.218.1 \
    --subnet=2001:db8:abc8::/64 \
    --gateway=2001:db8:abc8::10 \
     -o parent=eth0.218 \
     -o macvlan_mode=bridge macvlan216
```