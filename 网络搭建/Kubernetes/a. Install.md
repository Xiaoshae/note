# Install

在 Ubuntu 24.04 上使用 Kubeadm 安装 Kubernetes 集群。



1）设置主机名并更新 hosts 文件 

配置主节点和工作节点的主机名，并更新 hosts 文件以实现网络通信。 

```
sudo hostnamectl set-hostname "k8s-master"      // 主节点  
sudo hostnamectl set-hostname "k8s-node1"    // 工作节点1  
sudo hostnamectl set-hostname "k8s-node2"    // 工作节点2  
```



在每个节点的 /etc/hosts 文件中添加以下内容： 

```
10.40.1.240  k8s-master
10.40.1.241  k8s-node1
10.40.1.242  k8s-node2
```



3）关闭 Swap 分区并加载内核模块

禁用 Swap 分区

```
swapoff -a
sudo sed -i '/swap/s/^\(.*\)$/#\1/g' /etc/fstab
```



编辑 /etc/modules-load.d/containerd.conf 文件配置 overlay 和 br_netfilter 等内核模块。

```
vi /etc/modules-load.d/containerd.conf
```

```
overlay
br_netfilter
```

```
sudo modprobe overlay && sudo modprobe br_netfilter
```



接下来，添加 IP 转发等内核参数。创建文件并使用 sysctl 命令加载参数：   

```
sudo vi /etc/sysctl.d/kubernetes.conf  
```

```
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
```



运行以下命令加载内核参数：   

```
sudo sysctl --system
```



3）安装 Containerd   

安装并配置 Containerd，使用 SystemdCgroup 管理容器运行时。   

```
wget https://github.com/containerd/containerd/releases/download/v1.7.24/containerd-1.7.24-linux-amd64.tar.gz -P /tmp/
tar Cxzvf /usr/local /tmp/containerd-1.7.24-linux-amd64.tar.gz
wget https://raw.githubusercontent.com/containerd/containerd/main/containerd.service -P /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now containerd
```



生成 Containerd  配置文件，将 **SystemdCgroup = false 改为 true**

```
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml
sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml
```



将配置文件中的中 **registry.k8s.io/pause:3.8 改为 registry.k8s.io/pause:3.10**（ 3.8 改为 3.10 ）

```
sed -i 's/registry\.k8s\.io\/pause:3\.8/registry.k8s.io\/pause:3.10/g' /etc/containerd/config.toml
```



在 Containerd 配置镜像站，编辑 /etc/containerd/config.toml 文件，在 **[plugins."io.containerd.grpc.v1.cri".registry.mirrors]** 添加内容。

```
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
          endpoint = ["https://deng-registry-1-docker-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."ghcr.io"]
          endpoint = ["https://deng-ghcr-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."gcr.io"]
          endpoint = ["https://deng-gcr-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."quay.io"]
          endpoint = ["https://deng-quay-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.k8s.io"]
          endpoint = ["https://deng-registery-k8s.xiaoshae.cn"]
```

![image-20250417195824625](./images/a.%20Install.assets/image-20250417195824625.png)



重启 Containerd  

```
systemctl restart containerd
```



配置网络

```
wget https://github.com/opencontainers/runc/releases/download/v1.2.2/runc.amd64 -P /tmp/
install -m 755 /tmp/runc.amd64 /usr/local/sbin/runc

wget https://github.com/containernetworking/plugins/releases/download/v1.6.2/cni-plugins-linux-amd64-v1.6.2.tgz -P /tmp/
mkdir -p /opt/cni/bin
tar Cxzvf /opt/cni/bin /tmp/cni-plugins-linux-amd64-v1.6.2.tgz
```



4）添加 Kubernetes 软件包仓库   

```
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gpg
```



添加 kubernetes 源密钥

```
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL https://mirrors.tuna.tsinghua.edu.cn/kubernetes/core:/stable:/v1.32/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```



为 Ubuntu 24.04 下载并配置 Kubernetes 软件包仓库。   

```
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://mirrors.tuna.tsinghua.edu.cn/kubernetes/core:/stable:/v1.32/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
```





5）安装 Kubernetes 组件   

在所有节点上安装 Kubeadm、Kubelet 和 Kubectl，以管理 Kubernetes 集群。   

```
sudo apt update  
apt-get install -y kubelet=1.32.3-1.1 kubeadm=1.32.3-1.1 kubectl=1.32.3-1.1
apt-mark hold kubelet kubeadm kubectl
```



创建 /etc/crictl.yaml 文件添加以下内容，为 crictl 指定容器运行时和容器镜像的 unix socket 地址。

```
runtime-endpoint: "unix:///run/containerd/containerd.sock"
image-endpoint: "unix:///run/containerd/containerd.sock"
timeout: 2
debug: false
```



6）初始化 Kubernetes 集群  

使用 Kubeadm 初始化控制平面节点。   

```
kubeadm init --pod-network-cidr 10.10.0.0/16 --kubernetes-version 1.32.3 --node-name k8s-master
```



```
export KUBECONFIG=/etc/kubernetes/admin.conf
printf "\nexport KUBECONFIG=/etc/kubernetes/admin.conf\n" >> /root/.bashrc
```



```
wget https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/tigera-operator.yaml
kubectl create -f tigera-operator.yaml
```



```
wget https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/custom-resources.yaml
sed -i 's/192\.168\.0\.0\/16/10.10.0.0\/16/g' custom-resources.yaml
kubectl apply -f custom-resources.yaml
```



7）加入工作节点

在控制节点上输入以下命令，将生成的加入集群的命令在工作节点上执行，将工作节点添加到 Kubernetes 集群。   

```
kubeadm token create --print-join-command
```



在工作节点给上执行加入集群的命令

```
kubeadm join 10.40.1.240:6443 --token xxxxx --discovery-token-ca-cert-hash sha256:xxxxxx
```



### 镜像站配置

在 Containerd 配置镜像站，编辑 /etc/containerd/config.toml 文件，在 **[plugins."io.containerd.grpc.v1.cri".registry.mirrors]** 添加内容。（老方法）

```
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
          endpoint = ["https://deng-registry-1-docker-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."ghcr.io"]
          endpoint = ["https://deng-ghcr-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."gcr.io"]
          endpoint = ["https://deng-gcr-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."quay.io"]
          endpoint = ["https://deng-quay-io.xiaoshae.cn"]

        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.k8s.io"]
          endpoint = ["https://deng-registery-k8s.xiaoshae.cn"]
```



新方法

- **先移除旧配置文件**：将原配置中的 `mirrors` 部分移除，在 **[plugins."io.containerd.grpc.v1.cri".registry]** 后的 **config_path** 指定文件夹位置。。

```
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
```

建议使用 `/etc/containerd/certs.d` 作为 `config_path`，因为这是 containerd 的默认推荐目录。可以根据需要修改路径，但要确保该目录已存在。



在 `config_path` 指定的目录（例如 `/etc/containerd/certs.d`）下，为每个注册中心创建一个子目录。

为 docker.io 创建子目录和文件：

```
sudo mkdir -p /etc/containerd/certs.d/docker.io
sudo touch    /etc/containerd/certs.d/docker.io/hosts.toml
```



在 `hosts.toml` 文件中写入：

```
server = "https://docker.io"
[host."https://deng-registry-1-docker-io.xiaoshae.cn"]
  capabilities = ["pull", "resolve"]
```



如果您的**端点需要认证（例如，用户名/密码）**、**跳过证书验证**，可以在 `hosts.toml` 中添加更多配置，如：

```
server = "https://docker.io"
[host."https://deng-registry-1-docker-io.xiaoshae.cn"]
  capabilities = ["pull", "resolve"]
  username = "your-username"
  password = "your-password"
  skip_verify = true
```



保存所有更改后，重启 containerd 服务，让新配置生效：

```
systemctl restart containerd
```



在使用 ctr images pull 时必须使用 **--hosts-dir /etc/containerd/certs.d 指定目录**：

```
ctr images pull --hosts-dir /etc/containerd/certs.d docker.io/library/nginx:1.27.5-alpine3.21-slim
```

- **使用 crictl pull 则可以不指定**

