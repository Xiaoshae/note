# Init 容器

**Init 容器** 是一种特殊容器，在 **Kubernetes Pod** 中的应用容器启动之前运行。它主要用于执行一些初始化任务，例如包含应用镜像中不存在的实用工具、安装脚本或其他准备工作。这些容器确保 **Pod** 的环境正确设置后，才启动主应用容器。



> 在 Pod 的规约（spec）中，使用 `initContainers` 字段来定义。它是一个数组，与主应用容器的 `containers` 数组处于相同级别。



如果有多个**Init 容器**，它们会一个接一个地运行，只有前一个成功后，下一个才会启动。如果**Init 容器**失败，**Kubernetes** 会不断重启它（除非**Pod** 的 **restartPolicy** 设置为 "Never"，在这种情况下，整个**Pod** 会标记为失败）。



Pod 中的所有容器共享**资源** （如 **CPU** 、**内存**、**网络**）。假设 Pod 将**内存资源**限制为 **2G** ，如果 Pod 中存在两个主容器，那么这些主容器在运行时使用的内存总和不能超过 **2G** 。此外， **Init 容器** 作为 Pod 中的容器，也会受到相同的资源限制。



**Init 与普通容器**

Init 容器支持普通容器的大部分字段，例如**资源限制**、**数据卷**和**安全设置**。但 Init 容器不支持一些与生命周期相关的字段，包括 **lifecycle** （存活探针）、**livenessProbe** （就绪探针）和 **startupProbe** （启动探针）。这些探针用于监控容器运行状态，但 Init 容器不需要它们，因为仅需完成初始化任务。



**Init 与车边容器**

**边车容器**（sidecar container）是另一种特殊容器，它在主应用容器启动前运行，但会持续运行以辅助主容器，**边车容器**则会持续运行，与主应用容器一起存在，直到 **Pod** 结束。**Init 容器**与之不同，**Init 容器**仅在 **Pod** 初始化期间运行，完成任务后立即结束，不会与主应用容器并行运行。

**Init 容器**不支持 **lifecycle**、 **livenessProbe** 等探针，因为它不需要持续监控。**边车容器**支持这些探针，用于管理其生命周期。



### 使用 Init 容器的情况

下面的例子定义了一个具有 2 个 Init 容器的简单 Pod。 第一个等待 `myservice` 启动， 第二个等待 `mydb` 启动。 一旦这两个 Init 容器都启动完成，Pod 将启动 `spec` 节中的应用容器。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
  labels:
    app.kubernetes.io/name: MyApp
spec:
  containers:
  - name: myapp-container
    image: busybox:1.28
    command: ['sh', '-c', 'echo The app is running! && sleep 3600']
  initContainers:
  - name: init-myservice
    image: busybox:1.28
    command: ['sh', '-c', "until nslookup myservice.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for myservice; sleep 2; done"]
  - name: init-mydb
    image: busybox:1.28
    command: ['sh', '-c', "until nslookup mydb.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for mydb; sleep 2; done"]
```



**sh -c "xxx"** 是一种在命令行中使用 sh shell 解释器执行指定字符串 "xxx" 作为命令的简便方式，例如 **sh -c "echo Hello"** 会输出 Hello。

`until [command 1] ; do [command 2] ; [command 3] done` 是一种 **shell** 脚本的循环结构。如果 **[command 1]** 执行失败（**退出状态非0**），则执行一次 do 和 done 之间的命令，然后继续执行 **[command 1]** 命令，直到它执行成功（**退出状态0**）为止。

**nslookup** 是一个标准的网络诊断工具，用于进行 DNS 查询。如果查询到结果，则退出状态为 **0**；如果未查询到结果，则退出状态为非 **0**。

命令中的域名结构为：**mydb.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local**

**/var/run/secrets/kubernetes.io/serviceaccount/namespace** 是一个文件路径，在 Kubernetes Pod 中，这个文件由 Kubernetes 自动挂载。它包含了当前 Pod 运行所在的命名空间（Namespace）名称，例如 "default" 或 "production"。**cat** 命令用于读取这个文件的内容，因此如果 Pod 运行在 "default" 命名空间，命令会输出 "default"。

因此，$(...) 部分会被替换为实际的命名空间名称，整个域名会变成像 **"mydb.default.svc.cluster.local"** 这样的形式。

**.svc.cluster.local** 是 Kubernetes 默认的 DNS 域，用于服务发现（Service Discovery）。在 Kubernetes 中，服务可以通过这种格式的域名访问，例如 **"mydb.default.svc.cluster.local"** 表示在 "default" 命名空间中的 "mydb" 服务。

Kubernetes 的 DNS 服务（如 **CoreDNS**）会处理这种查询，将域名解析为服务的 Cluster IP（集群内部 IP 地址），从而允许 Pod 之间互相通信，而不需要硬编码 IP。



你通过运行下面的命令启动 Pod：

```shell
kubectl apply -f myapp.yaml
```



使用下面的命令检查其状态：

```shell
kubectl get -f myapp.yaml
```

```
NAME        READY     STATUS     RESTARTS   AGE
myapp-pod   0/1       Init:0/2   0          6m
```



或者查看更多详细信息：

```shell
kubectl describe -f myapp.yaml
```

```
Name:          myapp-pod
Namespace:     default
[...]
Labels:        app.kubernetes.io/name=MyApp
Status:        Pending
[...]
Init Containers:
  init-myservice:
[...]
    State:         Running
[...]
  init-mydb:
[...]
    State:         Waiting
      Reason:      PodInitializing
    Ready:         False
[...]
Containers:
  myapp-container:
[...]
    State:         Waiting
      Reason:      PodInitializing
    Ready:         False
[...]
Events:
  FirstSeen    LastSeen    Count    From                      SubObjectPath                           Type          Reason        Message
  ---------    --------    -----    ----                      -------------                           --------      ------        -------
  16s          16s         1        {default-scheduler }                                              Normal        Scheduled     Successfully assigned myapp-pod to 172.17.4.201
  16s          16s         1        {kubelet 172.17.4.201}    spec.initContainers{init-myservice}     Normal        Pulling       pulling image "busybox"
  13s          13s         1        {kubelet 172.17.4.201}    spec.initContainers{init-myservice}     Normal        Pulled        Successfully pulled image "busybox"
  13s          13s         1        {kubelet 172.17.4.201}    spec.initContainers{init-myservice}     Normal        Created       Created container init-myservice
  13s          13s         1        {kubelet 172.17.4.201}    spec.initContainers{init-myservice}     Normal        Started       Started container init-myservice
```



如需查看 Pod 内 Init 容器的日志，请执行：

```shell
kubectl logs myapp-pod -c init-myservice # 查看第一个 Init 容器
kubectl logs myapp-pod -c init-mydb      # 查看第二个 Init 容器
```

在这一刻，Init 容器将会等待至发现名称为 `mydb` 和 `myservice` 的服务。



创建 `mydb` 和 `myservice` 的服务 Service 的配置文件：

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myservice
spec:
  ports:
  - protocol: TCP
    port: 80
    targetPort: 9376
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mydb
spec:
  ports:
  - protocol: TCP
    port: 80
    targetPort: 9377
```



创建 `mydb` 和 `myservice` 服务的命令：

```shell
kubectl apply -f services.yaml
```



这样你将能看到这些 Init 容器执行完毕，随后 `my-app` 的 Pod 进入 `Running` 状态：

```shell
kubectl get -f myapp.yaml
```

```
NAME        READY     STATUS    RESTARTS   AGE
myapp-pod   1/1       Running   0          9m
```





只有所有 **Init 容器** 都成功运行后，Pod 才会进入 **Ready** 状态（表示它已准备好处理流量）。在此之前，Pod 会保持 **Pending** 状态（等待中），**Init 容器** 的端口不会被 **Service**（服务发现组件）收集或暴露。另外，Pod 的 **Initializing** 状态会设置为 false。

如果 Pod 重启，所有 Init 容器必须重新执行。

**Init 容器**可能多次运行（如重试时），所以它的代码必须是**幂等的** （**Idempotent**），即多次执行的结果相同，不能导致数据混乱。

如果代码向 **emptyDir** 卷（一种临时存储）写入文件，必须处理文件已存在的情况，以避免错误。因为 **Init 容器**崩溃后，**emptyDir** 卷中的数据会保持不变。这是因为 **emptyDir** 卷是 **Pod 级别的资源**，而不是容器级别的。

**Init 容器** 可以像普通应用容器一样使用大多数字段，但 **Kubernetes** 不允许使用 **readinessProbe** （就绪探针），因为 **Init 容器**的“就绪”状态只基于是否完成执行。如果试图添加它，**Kubernetes** 会校验失败并报错。

**activeDeadlineSeconds** 为整个 **Pod** 上设置一个总超时时间，包括 **Init 容器**的执行时间。如果超时，**Pod** 会被终止。建议只在特定场景（如 **Job** 类型应用）中使用 **activeDeadlineSeconds**，因为它会影响整个 **Pod** 的生命周期。如果 **Pod** 已运行正常，但超时了，它仍会被杀死。

**在 Pod 中的每个应用容器和 Init 容器的名称必须唯一**；如果与任何其它容器共享同一个名称，会在**校验时抛出错误**。