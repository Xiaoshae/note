# archlinux nvme-of

在 Arch Linux 上同时设置 NVMe-oF TCP 的目标端和连接端，并使用 `brd` 模块创建的内存块设备进行演示。

 一台 archlinux 同时为 nvme-of tcp 的目标端和连接端，使用 brd 模块创建一个 2G 的内存块设备，目标端共享出去，连接端连接到他。 

 连接成功后格式化为 ext4，挂载到 /mnt/ramdisk 路径。 



 一切简单方便为主。 

**讲个好东西：Soft-RoCE** 



## nvme-of over tcp

识别并加载模块

根据你使用的 NVMe-oF 传输类型，你需要加载相应的内核模块。最常见的两种传输类型是 TCP 和 RDMA。

- **对于 TCP 传输：**
  - **主机端 (Host)**：`nvme-tcp` 和 `nvme-fabrics`
  - **目标端 (Target)**：`nvmet-tcp` 和 `nvmet`
- **对于 RDMA 传输：**
  - **主机端 (Host)**：`nvme-rdma` 和 `nvme-fabrics`
  - **目标端 (Target)**：`nvmet-rdma` 和 `nvmet`



安装 `nvme-cli` 和 `nvmetcli` 工具

```
pacman -S nvme-cli
pacman -S nvmetcli
```



首先，我们需要加载 NVMe-oF 所需的内核模块

```
modprobe nvmet-tcp
modprobe nvmet
modprobe nvme-tcp
modprobe nvme-fabrics
```



### target

```
modprobe nvmet
modprobe nvmet-tcp
```

使用 `brd`（块设备 RAM 磁盘）模块创建一个 2GB 的内存块设备。

```
modprobe brd rd_nr=1 rd_size=2097152
```

`rd_nr=1` 表示创建一个设备。

`rd_size=2097152` 表示设备大小为 2097152 KB，即 2 GB。

加载成功后，您应该会看到 `/dev/ram0` 设备。



创建 10GB 设备

```
modprobe brd rd_nr=1 rd_size=10485760
```



接下来，使用 `nvmetcli` 将 `/dev/ram0` 导出为 NVMe-oF 目标。



**启动 `nvmetcli` 交互式模式**:

```
sudo nvmetcli
```



**创建子系统和命名空间**:

```
cd /subsystems
create my_ramdisk_nqn
cd my_ramdisk_nqn
set attr allow_any_host=1 # 允许任何主机连接
cd namespaces
create 1
cd 1
set device path=/dev/ram0
enable
```



**创建端口**:

这里我们为目标端配置一个 TCP 端口。由于是本机连接，我们使用 `127.0.0.1` 作为传输地址。

```
cd /ports
create 1
cd 1
set addr trtype=tcp
set addr adrfam=ipv4
set addr traddr=127.0.0.1
set addr trsvcid=4420
cd subsystems
create my_ramdisk_nqn
```



**保存配置并退出**:

```
saveconfig /etc/nvmet/config.json
exit
```



### client

```
modprobe nvme-tcp
modprobe nvme-fabrics
```

配置 NVMe-oF 连接端

现在，使用 `nvme-cli` 在同一台机器上连接到我们刚刚创建的目标端。

**发现目标**:

首先，您可以使用 `nvme discover` 命令来确认目标端是否可见。

```
sudo nvme discover --transport=tcp --traddr=127.0.0.1 --trsvcid=4420
```

如果配置正确，您应该能看到 `my_ramdisk_nqn` 的发现日志。



**建立连接**:

使用 `nvme connect` 命令连接到目标。

```
sudo nvme connect --transport=tcp --traddr=127.0.0.1 --nqn=my_ramdisk_nqn
```

连接成功后，系统会创建一个新的 NVMe 设备，通常命名为 `/dev/nvme0n1`。您同样可以使用 `lsblk` 命令验证。



格式化和挂载设备

最后，对新出现的 NVMe 设备进行格式化并挂载到指定路径。

```
sudo mkfs.ext4 /dev/nvme0n1
```



创建挂载点并挂载:

```
sudo mkdir -p /mnt/ramdisk
sudo mount /dev/nvme0n1 /mnt/ramdisk
```



**验证**:

使用 `df -h` 命令检查，您应该能看到 `/mnt/ramdisk` 已经成功挂载。

```
df -h
```



到此，您已经成功地在 Arch Linux 上使用 `brd` 模块创建的内存块设备，通过 NVMe-oF TCP 将其作为目标端共享，并在本机作为连接端连接、格式化和挂载。



### 断开

 nvme-of 客户端断开连接，目标端清除所有配置，删除 ram0 设备。 

客户端断开连接

首先，断开 NVMe-oF 客户端的连接，并卸载挂载点。



**卸载文件系统**:

如果 `/mnt/ramdisk` 还在挂载状态，你需要先卸载它。

```
sudo umount /mnt/ramdisk
```



**断开 NVMe-oF 连接**:

使用 `nvme disconnect` 命令断开连接。你可以通过设备名 (`/dev/nvme0`) 来指定要断开的控制器。

```
sudo nvme disconnect --device=/dev/nvme0
```

断开连接后，`/dev/nvme0` 和 `/dev/nvme0n1` 这些设备文件就会自动消失。



目标端清除配置

接下来，清除 NVMe-oF 目标端（Target）的配置。

**清除 `nvmetcli` 配置**:

使用 `nvmetcli clear` 命令可以快速清除当前正在运行的 NVMe-oF 目标配置。

```
sudo nvmetcli clear
```

这个命令会移除所有已配置的子系统、命名空间和端口。



**删除配置文件**:

如果你之前保存了配置文件，为了彻底清除，建议一并删除它。

```
sudo rm /etc/nvmet/config.json
```



移除内存块设备 `ram0`

最后，卸载并移除 `brd` 模块创建的内存块设备。



**卸载 `brd` 模块**:

你可以使用 `modprobe -r` 命令来卸载 `brd` 模块。这会自动销毁 `/dev/ram0` 设备。

```
sudo modprobe -r brd
```

**注意**：在卸载 `brd` 模块之前，确保没有任何程序正在使用 `/dev/ram0`，否则命令会失败。



卸载其他内核模块（可选）

如果你不再需要 NVMe-oF 功能，可以进一步卸载相关的内核模块。

```
sudo modprobe -r nvme-tcp
sudo modprobe -r nvmet-tcp
sudo modprobe -r nvmet
sudo modprobe -r nvme-fabrics
```

完成这些步骤后，你的系统就会恢复到初始状态，之前创建的 NVMe-oF 连接、目标配置和内存块设备都将被完全清除。



## nvme-of over Soft-RoCEv2

### target

```
modprobe nvmet_rdma
modprobe nvmet
modprobe nvmet-tcp
modprobe brd
```



创建一个 10GB 的内存块设备

```
modprobe brd rd_nr=1 rd_size=10485760
```



接下来，你需要配置 Soft-RoCE 网络接口。RoCEv2 需要支持 `netdev` 的 `rdma` 驱动，并配置相应的 IP 地址。

```
# 激活 Soft-RoCE 设备
rdma link add rxei0 type rxe netdev ens192
```

注意：将 ens192 替换为你的实际网卡名称



确认设备状态

```
rdma link show
```



NVMe-oF Target

现在，使用 `nvmetcli` 交互模式来创建和配置 NVMe-oF Target。

```
nvmetcli

# 进入 subsystems 目录
cd /subsystems

# 创建一个 NVMe Qualified Name (NQN) 子系统
create nqn.2025-08.com.example:test

# 进入新创建的子系统
cd nqn.2025-08.com.example:test

# 允许任意主机连接（如果需要更严格的控制，可以设置为 0）
set attr allow_any_host=1

# 进入 namespaces 目录
cd namespaces

# 创建一个 namespace，分配一个 ID
create 1

# 进入新的 namespace
cd 1

# 将内存块设备 `/dev/brd0` 绑定到 namespace
set device path=/dev/brd0

# 启用 namespace
enable

# 返回到根目录
cd /

# 进入 ports 目录
cd /ports

# 创建一个 port
create 1

# 进入 port
cd 1

# 设置传输类型为 rdma
set addr trtype=rdma

# 设置地址族为 ipv4
set addr adrfam=ipv4

# 设置 target 的 IP 地址
set addr traddr=192.168.1.1

# 设置服务 ID，NVMe-oF over RoCE 默认端口是 4420
set addr trsvcid=4420

# 进入 subsystems 目录并绑定刚刚创建的子系统
cd subsystems

# 将子系统绑定到 port
create nqn.2025-08.com.example:test

# 保存配置以备将来使用
saveconfig roce_config.json

# 退出 nvmetcli
exit
```



### Client

首先，加载客户端所需的内核模块。

```
modprobe nvme-rdma
modprobe nvme-tcp
modprobe nvme-fabrics
```



使用 `nvme-cli` 工具来发现和连接目标。

使用 nvme-cli 发现 target

```
nvme discover --transport=rdma --traddr=192.168.1.1 --trsvcid=4420
```



连接到 target

```
nvme connect --transport=rdma --traddr=192.168.1.1 --trsvcid=4420 --subnqn=nqn.2025-08.com.example:test
```

连接成功后，你的客户端机器上应该会出现一个新的 NVMe 设备，通常命名为 `/dev/nvmeXnY`，你可以像使用本地块设备一样使用它。你可以使用 `nvme list` 命令来验证连接是否成功。

