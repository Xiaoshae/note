# kubectl

kubectl 是 k8s 的官方命令行接口（CLI），使用 Kubernetes API 与 Kubernetes 集群的控制面进行通信，用于执行几乎所有集群操作，包括创建、查看、更新、删除资源，以及调试和监控。



大多数 kubectl 命令通常可以分为以下几类：

| 类型             | 用途                    | 描述                                           |
| ---------------- | ----------------------- | ---------------------------------------------- |
| 声明式资源管理   | 部署和运维（如 GitOps） | 使用资源管理声明式管理 Kubernetes 工作负载     |
| 命令式资源管理   | 仅限开发环境            | 使用命令行参数和标志来管理 Kubernetes 工作负载 |
| 打印工作负载状态 | 调试                    | 打印有关工作负载的信息                         |
| 与容器交互       | 调试                    | 执行、挂接、复制、日志                         |
| 集群管理         | 集群运维                | 排空和封锁节点                                 |



使用以下语法从终端窗口运行 `kubectl` 命令：

```shell
kubectl [子命令] [资源类型] [资源名称] [flags]
```

```
kubectl [子命令] [全局参数]　[子命令参数] [资源类型] [资源名称] [flags]
```

kubectl 的参数分为两类：**全局参数**（适用于所有子命令）和**子命令参数**（特定于每个子命令）。部分全局参数可以位于子命令前面。



其中 `子命令`、`资源类型`、`资源名称` 和 `flags` 分别是：

- **全局参数**：如 **--namespace 或 -n**：指定操作的命名空间（k8s 的资源隔离机制）

- **子命令**：指定要对一个或多个资源执行的操作，例如 `create`、`get`、`describe`、`delete`。

- **子命令参数**：如在 **"get pods"** 中的 **"pods" 就是子命令 "get" 的参数**。

- **资源类型**：指定资源类型。资源类型不区分大小写， 可以指定单数、复数或缩写形式。例如，以下命令输出相同的结果：

    ```
    kubectl get pod pod1
    kubectl get pods pod1
    kubectl get po pod1
    ```

- **资源名称**：指定资源的名称。名称区分大小写。 如果省略名称，则显示所有资源的详细信息。例如：`kubectl get pods`。

- `flags`： 指定可选的参数。例如，可以使用 `-s` 或 `--server` 参数指定 Kubernetes API 服务器的地址和端口。



## 参考

```
kubectl 控制 Kubernetes 集群管理器。

在以下处查找更多信息： https://kubernetes.io/docs/reference/kubectl/

基本命令（初级）：
  create          从文件或标准输入创建资源
  expose          将复制控制器、服务、部署或 pod 暴露为新的 Kubernetes 服务
  run             在集群上运行特定镜像
  set             为对象设置特定功能

基本命令（中级）：
  explain         获取资源的文档说明
  get             显示一个或多个资源
  edit            编辑服务器上的资源
  delete          通过文件名、标准输入、资源和名称，或通过资源和标签选择器删除资源

部署命令：
  rollout         管理资源的滚动更新
  scale           为部署、副本集或复制控制器设置新规模
  autoscale       为部署、副本集、有状态集或复制控制器自动缩放

集群管理命令：
  certificate     修改证书资源
  cluster-info    显示集群信息
  top             显示资源（CPU/内存）使用情况
  cordon          将节点标记为不可调度
  uncordon        将节点标记为可调度
  drain           为维护做准备时清空节点
  taint           更新一个或多个节点的污点

故障排除和调试命令：
  describe        显示特定资源或资源组的详细信息
  logs            打印 pod 中容器的日志
  attach          附加到运行中的容器
  exec            在容器中执行命令
  port-forward    将一个或多个本地端口转发到 pod
  proxy           运行到 Kubernetes API 服务器的代理
  cp              复制文件和目录到容器或从容器复制
  auth            检查授权
  debug           为工作负载和节点创建调试会话
  events          列出事件

高级命令：
  diff            比较实时版本与待应用版本的差异
  apply           通过文件名或标准输入将配置应用到资源
  patch           更新资源的字段
  replace         通过文件名或标准输入替换资源
  wait            实验性：等待一个或多个资源满足特定条件
  kustomize       从目录或 URL 构建 kustomization 目标

设置命令：
  label           更新资源的标签
  annotate        更新资源的注解
  completion      为指定 shell（bash、zsh、fish 或 powershell）输出 shell 补全代码

插件提供的子命令：

其他命令：
  api-resources   打印服务器上支持的 API 资源
  api-versions    以“组/版本”形式打印服务器上支持的 API 版本
  config          修改 kubeconfig 文件
  plugin          提供与插件交互的实用工具
  version         打印客户端和服务器版本信息

用法：
  kubectl [flags] [options]

使用 “kubectl <command> --help” 获取给定命令的更多信息。
使用 “kubectl options” 获取全局命令行选项列表（适用于所有命令）。
```



### get

`get` 命令用于获取 Kubernetes 集群中指定资源的列表或详细信息。它提供了一个快速的概述，帮助您查看资源的当前状态，而不深入到详细配置。

```
kubectl get [资源类型] [资源名称] [选项]
```

- **[资源类型]**：指定您要获取的资源种类，例如：
    - `pods` 或 `po`（缩写）。
    - `deployments` 或 `deploy`。
    - `nodes` 或 `no`。
    - `services`、`configmaps`、`secrets` 等常见资源。
    - 如果不指定资源名称，命令会列出该类型的所有资源。
- **[资源名称]**：可选。如果指定，会只显示该特定资源的详细信息。
- **[选项]**：用于自定义输出格式、范围等。常见选项如下。



- **-n 或 --namespace [命名空间]**：指定资源所在的命名空间（namespace）。默认是 `default`。例如，如果您的 Pod 在 `default` 命名空间中，使用 `-n default`。
- **-o 或 --output [格式]：**控制输出格式。常用格式包括：
    - `wide`：扩展输出，显示更多细节（如 IP 地址）。
    - `yaml`：以 YAML 格式输出，便于复制或编辑。
    - `json`：以 JSON 格式输出。
    - `name`：只输出资源名称。
- **--all-namespaces**：查看所有命名空间下的资源，而不限于当前命名空间。
- **-w 或 --watch**：实时监控资源变化。命令会持续运行，直到您按 Ctrl-C 停止。
- **-l 或 --selector [标签选择器]**：使用标签（labels）过滤资源。例如，只获取特定标签的 Pod。
- **--show-labels**：在输出中显示资源的标签。
- **-A**：等同于 `--all-namespaces`，用于查看所有命名空间。
- **--field-selector**：根据特定字段过滤资源，例如 `kubectl get pods --field-selector=status.phase=Running` 只显示运行中的 Pod。



### describe

`describe` 命令显示指定资源的详细摘要，包括其当前状态、配置细节、关联事件和元数据。

在部署应用时（如 Pod 卡在 ContainerCreating 状态），`describe` 可以显示事件日志，揭示问题原因（如镜像拉取失败或资源不足）。

```
kubectl describe [资源类型] [资源名称] [选项]
```

- **[资源类型]**：指定您要描述的资源种类，例如：
    - `pods` 或 `po`（缩写）。
    - `deployments` 或 `deploy`。
    - `nodes` 或 `no`。
    - `services`、`configmaps`、`persistentvolumes` 等。
    - 如果不指定资源名称，命令会提示错误；必须指定一个或多个资源。
- **[资源名称]**：资源的具体名称，例如 `kubernetes-bootcamp-9bc58d867-wmnvb`。
- **[选项]**：用于自定义行为。常见选项包括：
    - **-n 或 --namespace [命名空间]**：指定资源所在的命名空间，默认是 `default`。
    - **--show-events**：默认启用，显示与资源相关的事件日志。如果您不想显示，可以用 `--show-events=false`。
    - **-o 或 --output [格式]**：虽然 `describe` 主要输出人类可读的文本，但您可以用 `-o yaml` 或 `-o json` 获取结构化输出（不过这不如直接文本描述常见）。
    - **-l 或 --selector [标签选择器]**：如果不指定资源名称，可以用标签过滤多个资源，例如 `kubectl describe pods -l app=kubernetes-bootcamp`。
    - **--all-namespaces**：查看所有命名空间下的资源（但通常需要结合资源类型）。



## 声明式应用管理

管理资源的首选方法是配合 kubectl **Apply** 命令一起使用名为资源的声明式文件。 此命令读取本地（或远程）文件结构，并修改集群状态以反映声明的意图。



## 打印工作负载状态 

用户需要查看工作负载状态。

- 打印关于资源的摘要状态和信息
- 打印关于资源的完整状态和信息
- 打印资源的特定字段
- 查询与标签匹配的资源



## 调试工作负载

kubectl 支持通过提供以下命令进行调试：

- 打印 Container 日志
- 打印集群事件
- 执行或挂接到 Container
- 将集群中 Container 中的文件复制到用户的文件系统



## 集群管理 

有时用户可能需要对集群的节点执行操作。 kubectl 支持使用命令将工作负载从节点中排空，以便节点可以被停用或调试。

