# Kubernetes

## 组件

![Kubernetes 的组件](./images/a.%20%E6%A6%82%E8%BF%B0.assets/components-of-kubernetes.svg)

Kubernetes 集群由**控制平面**和**一个或多个工作节点（Node）**组成，各组件协同工作以管理和运行容器化应用。

- **控制平面**可以由 **一台或多台物理机或虚拟机** 组成，负责管理集群的整体状态和调度，例如：控制 Node。
- 每个 **Node** 是一台 **物理机或虚拟机**，用于运行实际的业务容器。



一个 最小的 Kubernetes 集群至少需要**一台物理主机**，这台主机上同时运行**控制平面组件和Node组件**。



### 控制平面组件

控制平面管理集群的整体状态：

- **kube-apiserver**：公开 Kubernetes HTTP API 的核心组件服务器
- **etcd**：具备一致性和高可用性的键值存储，用于所有 API 服务器的数据存储
- **kube-scheduler**：查找尚未绑定到节点的 Pod，并将每个 Pod 分配给合适的节点。
- **kube-controller-manager**：运行控制器来实现 Kubernetes API 行为。
- **cloud-controller-manager (optional)**：与底层云驱动集成



### Node 组件

在每个**节点（物理机或虚拟机）**上运行，维护运行的 Pod 并提供 Kubernetes 运行时环境：

- **kubelet**：确保 Pod 及其容器正常运行。
- **kube-proxy（可选）**：维护节点上的网络规则以实现 Service 的功能。
- **Container runtime**：负责运行容器的软件，阅读容器运行时以了解更多信息。



### Pod

**Pod** 是可以在 Kubernetes 中创建和管理的、最小的可部署的**计算单元**。

**Pod**（就像在鲸鱼荚或者豌豆荚中）是**一组（一个或多个）容器**； 这些容器**共享存储**、**网络**、以及**怎样运行这些容器的规约**。



Pod 中的内容总是并置（colocated）的并且**一同调度**，在**共享的上下文**中运行。 

- **一同调度**：Pod 内的所有容器共享相同的生命周期。当 Pod 被创建、启动、停止或删除时，所有容器都会同时经历这些状态变化。
- **共享上下文** 指的是 Pod 内的容器共享一些共同的资源和环境设置：
    - **网络命名空间**：每个 Pod 都有一个唯一的 IP 地址和网络命名空间。Pod 内的所有容器共享这个网络命名空间，因此它们可以通过 `localhost` 相互通信，而无需额外的网络配置。
    - **存储卷**：Pod 可以定义一个或多个存储卷，这些卷可以被 Pod 内的所有容器挂载和访问。存储卷可以是临时的（如空目录 `emptyDir`），也可以是持久化的（如持久卷 `PersistentVolume`）。



Pod 可以理解为**运行特定应用的 “逻辑主机”**，其中包含一个或多个应用容器， 这些容器相对紧密地耦合在一起。

在**传统环境**中，如果你有几**个相关的程序（比如一个 Web 应用和它的日志收集工具）**，你通常会把它们**部署在同一台物理机或虚拟机**上，因为它们需要密切合作。

Kubernetes 中将**多个容器部署在同一个 Pod** 上，类似于**传统环境**中将**多个相关的应用程序部署在一台机器上**。



### service & Ingress



### configMap & secret



### Volume



### Deployment & StatefulSet



### install

#### 操作

系统：Ubuntu Server 24.04.1 LTS

K8s版本：Kubernetes 1.31



环境：

控制平面：192.168.20.101

计算节点1：192.168.20.102

计算节点2：192.168.20.103



以下操作为 3 台机器同时进行：



两个命令二选一执行：

1. 修改 /etc/hosts 文件，添加以下三行：

```
192.168.20.101 k8s-control
192.168.20.102 k8s-1
192.168.20.103 k8s-2
```

2. 快速修改添加内容到 hosts：

```
printf "\n192.168.20.101 k8s-control\n192.168.20.102 k8s-1\n192.168.20.103 k8s-2\n\n" >> /etc/hosts
```



修改 /etc/modules-load.d/containerd.conf 文件（如果不存在，自行创建该文件）

添加以下内容：

```
overlay
br_netfilter
```

快速添加：

```
printf "overlay\nbr_netfilter\n" >> /etc/modules-load.d/containerd.conf
```



执行以下命令，使刚刚的修改生效：

```
modprobe overlay
modprobe br_netfilter
```





添加以下内容到 /etc/sysctl.d/99-kubernetes-cri.conf 文件中（如果不存在，自行创建，大概率不存在）

```
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
```

执行命令，应用刚刚的修改

```
sysctl --system
```



提前下载这几个文件：

```
https://github.com/containerd/containerd/releases/download/v1.7.24/containerd-1.7.24-linux-amd64.tar.gz
https://raw.githubusercontent.com/containerd/containerd/main/containerd.service
```



执行命令：

```
tar Cxzvf /usr/local /you/path/containerd-1.7.24-linux-amd64.tar.gz
```

将 /you/path/containerd-1.7.24-linux-amd64.tar.gz 替换为你实际的路径。



将 containerd.service 文件移动到 /etc/systemd/system/ 目录中

```
mv /you/path/containerd.service /etc/systemd/system/.
```

执行以下两条命令：

```
systemctl daemon-reload
systemctl enable --now containerd
```



下载两个文件

```
https://github.com/opencontainers/runc/releases/download/v1.2.2/runc.amd64
https://github.com/containernetworking/plugins/releases/download/v1.6.1/cni-plugins-linux-amd64-v1.6.1.tgz
```

执行命令：

```
install -m 755 /you/path/runc.amd64 /usr/local/sbin/runc
```

将 /you/path/runc.amd64 替换为你实际 runc.amd64 路径



执行命令：

```
mkdir -p /opt/cni/bin
tar Cxzvf /opt/cni/bin /you/path/cni-plugins-linux-amd64-v1.6.1.tgz
```

将 /you/path/cni-plugins-linux-amd64-v1.6.1.tgz 替换为你实际的 cni-plugins-linux-amd64-v1.6.1.tgz 路径



执行命令：

```
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml
```

编辑 **/etc/containerd/config.toml** 文件：

将 **139** 行的 **SystemdCgroup = false** 改为 **SystemdCgroup = true**。

![image-20241217180243886](./images/a.%20%E6%A6%82%E8%BF%B0.assets/image-20241217180243886.png)

执行命令：

```
systemctl restart containerd
```



关闭虚拟内存

```
swapoff -a
```

或者注释 /etc/fstab 的（重启生效）。

![image-20241217180426414](./images/a.%20%E6%A6%82%E8%BF%B0.assets/image-20241217180426414.png)



执行命令

```
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gpg
```



添加 kubernetes 源密钥

```
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL https://mirrors.tuna.tsinghua.edu.cn/kubernetes/core:/stable:/v1.31/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```

添加 kubernetes 源

```
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://mirrors.tuna.tsinghua.edu.cn/kubernetes/core:/stable:/v1.31/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
```



更新源：

```
apt-get update
```



重启（三台）：

```
reboot
```





安装 kubernetes ：

```
apt-get install -y kubelet=1.31.3-1.1 kubeadm=1.31.3-1.1 kubectl=1.31.3-1.1
```

设置 kubernetes 不自动更新：

```
apt-mark hold kubelet kubeadm kubectl
```



基础设置已完成。

剩下的步骤首先在，k8s-control 中执行：

```
kubeadm init --pod-network-cidr 10.10.0.0/16 --kubernetes-version 1.31.3 --node-name k8s-control
```



注意：在这些过程中会从国外源拉取镜像，基本上拉去不成功。

k8s-control 需要以下镜像：

```
IMAGE                                     TAG                 IMAGE ID            SIZE
docker.io/calico/apiserver                v3.29.1             421726ace5ed1       43.5MB
docker.io/calico/cni                      v3.29.1             7dd6ea186aba0       97.6MB
docker.io/calico/csi                      v3.29.1             bda8c42e04758       9.4MB
docker.io/calico/kube-controllers         v3.29.1             6331715a2ae96       35.6MB
docker.io/calico/node-driver-registrar    v3.29.1             8b7d18f262d5c       12MB
docker.io/calico/node                     v3.29.1             feb26d4585d68       143MB
docker.io/calico/pod2daemon-flexvol       v3.29.1             2b7452b763ec8       6.86MB
docker.io/calico/typha                    v3.29.1             4cb3738506f5a       31.3MB
quay.io/tigera/operator                   v1.36.2             3045aa4a360d4       21.8MB
registry.k8s.io/coredns/coredns           v1.11.3             c69fa2e9cbf5f       18.6MB
registry.k8s.io/etcd                      3.5.15-0            2e96e5913fc06       56.9MB
registry.k8s.io/kube-apiserver            v1.31.3             f48c085d70203       28MB
registry.k8s.io/kube-controller-manager   v1.31.3             b2a5ab7b1d92e       26.1MB
registry.k8s.io/kube-proxy                v1.31.3             9c4bd20bd3676       30.2MB
registry.k8s.io/kube-scheduler            v1.31.3             bab83bb0895ef       20.1MB
registry.k8s.io/pause                     3.10                873ed75102791       320kB
registry.k8s.io/pause                     3.8                 4873874c08efc       311kB
```



k8s-1 和 k8s-2 中需要以下镜像：

```
IMAGE                                    TAG                 IMAGE ID            SIZE
docker.io/calico/cni                     v3.29.1             7dd6ea186aba0       97.6MB
docker.io/calico/csi                     v3.29.1             bda8c42e04758       9.4MB
docker.io/calico/node-driver-registrar   v3.29.1             8b7d18f262d5c       12MB
docker.io/calico/node                    v3.29.1             feb26d4585d68       143MB
docker.io/calico/pod2daemon-flexvol      v3.29.1             2b7452b763ec8       6.86MB
docker.io/calico/typha                   v3.29.1             4cb3738506f5a       31.3MB
registry.k8s.io/kube-proxy               v1.31.3             9c4bd20bd3676       30.2MB
registry.k8s.io/pause                    3.8                 4873874c08efc       311kB
```



在 k8s-control 中执行命令：

```
kubeadm token create --print-join-command
```

生成计算节点加入集群的命令

```
kubeadm join 192.168.20.101:6443 --token cxxxxx.xxxxxxxwaz --discovery-token-ca-cert-hash sha256:36xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxd5 
```

![image-20241217181525732](./images/a.%20%E6%A6%82%E8%BF%B0.assets/image-20241217181525732.png)



在计算节点 k8s-1 和 k8s-2 中执行上面生成的命令，加入集群：

```
kubeadm join 192.168.20.101:6443 --token cxxxxx.xxxxxxxwaz --discovery-token-ca-cert-hash sha256:36xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxd5 
```



将 k8s-1 和 k8s-2 

```
kubectl label node k8s-1 node-role.kubernetes.io/worker=worker
kubectl label node k8s-2 node-role.kubernetes.io/worker=worker
```

