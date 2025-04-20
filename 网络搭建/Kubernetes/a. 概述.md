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



### Node

**Node** 是一台**计算机（物理或虚拟的）**。

- **Control Plane（Master Node）** – 就像**管理者**，负责组织和调度工作。
- **Worker Node** – 就像**员工**（机器），实际运行Pod中的应用程序。



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



### Cluster

**Kubernetes Cluster（集群）**，将一切整合在一起，包括Node、Pod、网络、存储和安全措施。



### Deployment

**Deployment（部署）** 确保始终有特定数量的**Pod** 在运行，同时自动化处理更新和扩展。



### ReplicaSet

**ReplicaSet（备份系统）**确保正确数量的**相同Pod** 始终在运行。



### Service

**Service** 确保用户始终能连接到正确的Pod，即使Pod重启或迁移到其他Node。



### Ingress

**Ingress** 管理外部用户访问服务的流量，确保网络请求得到正确的引导。



### ConfigMap

**ConfigMap** 将配置设置与应用程序分开存储，这样就能在不修改代码的情况下进行更改。



### Secret

**Secret** 用于安全存储敏感数据，如密码、API密钥和证书。



### PV

**Persistent Volume (PV)** 是一种长期存储，即使应用程序重启也不会消失。



### Namespace

**Namespace** 帮助在同一个 Kubernetes Cluster 中隔离不同的项目或团队。

