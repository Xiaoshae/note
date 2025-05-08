# Spec 规约

一个简单的 Pod 规约

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sleep
  namespace: default # Pod is a namespaced a resource
spec:
  containers:
    - name: pods-sleep
      image: busybox
      command:
        - sleep
        - '3600'
```



## activeDeadlineSeconds

**activeDeadlineSeconds | integer**

指定 Pod 启动后可以运行的最长秒数。一旦 Pod 的运行时间超过了这个设定的秒数，Kubernetes 会自动将该 Pod 标记为失败并终止它。



## containers

**containers | Container[]**

`containers` 字段用于定义 Pod 中包含的容器列表。



### name

**containers.name | string**

指定容器名称的字段，名称必须符合 DNS_LABEL 的格式要求。在同一个 Pod 中，每个容器必须有唯一的名称。一旦设置，这个名称就不能被更新（Immutable）。



### image

**containers.image | string**

指定容器的镜像名称，例如： `nginx:latest`



### imagePullPolicy 

**containers.imagePullPolicy | string**

定义 Kubernetes 何时从镜像仓库（如Docker Hub）拉取容器镜像，选项：

- **Always**：总是尝试从镜像仓库拉取镜像，即使本地已有镜像。这适合于需要确保使用最新镜像的场景。
- **Never**：从不从镜像仓库拉取镜像，只使用本地已有的镜像。如果镜像不存在，Pod会失败启动。
- **IfNotPresent**：如果本地没有镜像，才从仓库拉取；如果本地已有镜像，则直接使用。



如果镜像标签是 `:latest`，则默认值为 `Always`；否则，默认值为 `IfNotPresent`。



### restartPolicy

**containers.restartPolicy | string**

**RestartPolicy** 定义了 Pod 中单个容器的重启行为。此字段仅可为 **init 容器**设置，且唯一允许的值是 **"Always"**。对于非 **init 容器**或当此字段未指定时，重启行为则由 Pod 的重启策略和容器类型决定。将 **RestartPolicy** 设置为 **"Always"** 时，该 **init 容器**会在退出后不断重启，直至所有常规容器终止。一旦所有常规容器完成，所有具有 **restartPolicy "Always"** 的 **init 容器**将被关闭。这种生命周期不同于标准的 **init 容器**，通常被称为 "sidecar" 容器。尽管该 **init 容器**仍按 **init 容器**序列启动，但不会等待其完成，而是立即启动下一个 **init 容器**，或在任何 startupProbe 成功完成后再启动。



### command

**containers.command | string[]**

`command` 是一个字符串数组（string[]），用于指定容器在启动时要执行的命令。它类似于 Docker 中的 ENTRYPOINT，但不直接在 shell 中执行。如果未提供 `command`，Kubernetes 会使用容器镜像中定义的 ENTRYPOINT。



### args

**containers.args | string[]**

args 是一个字符串数组（string[]），用于指定传递给容器入口点（Entrypoint）的参数。如果未提供 args，Kubernetes 会使用容器镜像中定义的 CMD 指令作为默认参数。



### env

**containers.env | env[]**

`env` 是一个 EnvVar[] 数组，表示要在容器中设置的环境变量列表。这些变量会在容器启动时应用，用于配置容器行为。一旦 Pod 被创建，`env` 字段中的环境变量无法被修改。

```yaml
env:
  - name: username
    value: admin
  - name: password
    value: P2mbL231jU0k3a0o
```



**.env.name | string**

环境变量的名称。必须符合 C_IDENTIFIER 规则.



**.env.value | string**

指定变量的具体值，默认值为**空字符串**。



**.env.valueFrom | EnvVarSource**

指定环境变量的值来源，而不是直接提供一个字符串值。这允许从外部资源（如 ConfigMap、Secret 等）获取值。



### envFrom

**containers.envFrom | EnvFromSource[]**

**EnvFrom** 是一个数组（EnvFromSource[]），用于指定多个来源来填充容器中的环境变量。



**.envFrom.configMapRef | ConfigMapEnvSource**

`configMapRef` 用于从一个ConfigMap中提取键值对，并将其作为环境变量注入容器。



**.envFrom.prefix | string**

可选的前缀，会添加到ConfigMap中每个键的前面。

必须是一个有效的C标识符。例如，如果ConfigMap中有键 "KEY1"，并设置 prefix 为 "APP_"，则环境变量会变为 "APP_KEY1"。



**.envFrom.secretRef | SecretEnvSource**

从 Secret 中提取键值对，并将其作为环境变量注入容器。



### ports

**containers.ports | ContainerPort[]**

`ports` 是一个数组，用于指定 Pod 中的容器需要暴露的端口列表。数组的每个元素是一个对象，通常包含以下子字段。

```yaml
ports:
  - container: 80
    hostPort: 80
    hostIP: "0.0.0.0"
    name: http
    protocol: TCP
```



**.ports.container | integer**

这是容器内部监听和暴露的端口号。它表示容器在 Pod 的 IP 地址上运行的端口。



**.ports.hostIP| string**

hostIP 指的是 Node 的 IP 地址，`hostIP` 是一个可选字符串字段，用于指定将 `hostPort` 绑定到主机上的哪个 IP 地址。



**.ports.hostPort | integer**

这是将容器端口直接映射到主机（宿主机）的端口号。例如，如果设置 `hostPort: 8080`，则容器端口会直接绑定到主机的 8080 端口。



**.ports.name | string**

`name` 是一个可选字符串字段，用于给端口起一个唯一的名称。必须是有效的 IANA 服务名称（例如 "http" 或 "ssh"），并且在同一个 Pod 中必须唯一。每个 Pod 中的端口名称不能重复。



**.ports.protocol | string**

指定端口使用的网络协议。必须是 "UDP"、"TCP" 或 "SCTP"。默认值为 "TCP"。



### workingDir

**containers.workingDir | string**

- **描述**：指定容器的默认工作目录。如果未设置，将使用容器运行时的默认目录，通常由容器镜像配置决定。
- **默认值**：未指定时，使用容器运行时的默认值。



### volumeMounts

**containers.volumeMounts | VolumeMount[]**

卷挂载列表，用于将Pod中的卷（如PersistentVolume）挂载到容器的文件系统。挂载后，容器可以读写这些卷的内容。该字段不可更新（即，一旦Pod创建，不能修改）。



**.volumeMounts.mountPath | string**

指定卷在容器内部的挂载路径。例如，设置为 `/mnt/data`，表示卷将被挂载到容器的 `/mnt/data` 目录。



**.volumeMounts.name | string**

必须与Pod中定义的Volume的名称匹配。例如，如果Pod有一个名为 `my-volume` 的Volume，则这里的name应设置为 `my-volume`。



**.volumeMounts.mountPropagation | string**

当将一个卷（Volume）挂载到容器时，挂载操作如何在主机和容器之间传播。简单来说，它控制了文件系统挂载的“共享”或“隔离”行为。

- `None`（默认）：不传播挂载。主机和容器之间的挂载是独立的。
- `HostToContainer`：主机上的新挂载会传播到容器，但容器上的挂载不会传播回主机。
- `Bidirectional`：主机和容器之间的挂载可以双向传播，即主机上的挂载会影响容器，容器上的挂载也会影响主机。



**.volumeMounts.readOnly | boolean**

如果设置为 `true`，则卷以只读模式挂载；否则，以读写模式挂载（默认是 `false`）。这用于保护数据不被意外修改。



**.volumeMounts.recursiveReadOnly | string**

指定只读挂载是否递归应用。只有当 `readOnly` 为 `true` 时，此字段才生效：

- **Disabled**（默认值）：不进行递归只读挂载。
- **IfPossible**：如果容器运行时支持，则进行递归只读挂载；否则，不强制。
- **Enabled**：如果支持，则必须进行递归只读挂载；否则，Pod将启动失败并报错。

**注意**：如果设置为 `IfPossible` 或 `Enabled`，则 `mountPropagation` 必须为 `None`。如果 `readOnly` 为 `false`，此字段必须留空。



**非递归（Non-Recursive）**：只对挂载的顶层目录应用只读。例如，如果您挂载路径为 `/mnt/data`，只有 `/mnt/data` 本身是只读，但 `/mnt/data/subdir/file.txt` 可能仍然是可写的（取决于底层文件系统）。

**递归（Recursive）**：对整个目录树应用只读。例如，挂载 `/mnt/data` 后，不仅 `/mnt/data` 是只读，里面的所有子目录（如 `/mnt/data/subdir`）和文件（如 `/mnt/data/subdir/file.txt`）也都变为只读。容器无法对任何部分进行写入操作。



**.volumeMounts.subPath | string**

指定卷内部的子路径作为挂载点，默认是根路径。

假设您有一个Pod，使用一个名为 `my-volume` 的卷（例如来自一个PVC），默认会挂载整个卷。指定 `subPath: data` 来只挂载卷中 /data 目录下的文件。



**.volumeMounts.subPathExpr | string**

类似于 `subPath`，但支持环境变量扩展。它会根据容器的环境变量进行替换，默认是根路径。

**注意**：`subPathExpr` 和 `subPath` 互斥，不能同时使用。



### lifecycle

**containers.lifecycle | Lifecycle**

lifecycle 是容器生命周期钩子（lifecycle hooks），用于在容器创建、启动或终止时运行自定义命令或操作。如果钩子失败，可能影响容器的行为（如重启或终止）。



#### postStart

**.lifecycle.postStart | ExecAction**

容器创建后立即执行。该钩子在容器启动后马上运行，如果钩子失败，容器将被终止并根据其重启策略（restart policy）重新启动。其他容器管理操作（如就绪检查）会等待钩子完成。



##### exec

**.lifecycle.postStart.exec | ExecAction**

在容器内执行命令。



**.exec.command | string[]**

一个字符串数组，表示要执行的命令行。

示例：`["/bin/sh", "-c", "echo Hello"]`



命令直接执行，不通过 shell，因此不支持管道符（如 `|`）。如果需要 shell，支持，请显式调用 shell。

示例：`["/bin/sh", "-c", "your command"]`



退出状态码为 0 表示成功，否则视为失败。



##### httpGet

**.lifecycle.postStart.httpGet | HTTPGetAction**

发送 HTTP GET 请求。

```yaml
portStart:
  HttpGet:
    host: 127.0.0.1
    HttpHeader:
      - name: Host
        value: "example.com"
      - name: content-type
        value: "application/x-www-form-urlencoded"
    path: "/lifecycle"
    port: 443           # <--- 可以用 https 替换
    scheme: https
```



**.httpGet.host | string**

连接的主机名，默认使用 Pod IP。建议在 httpHeaders 中设置 Host。



**.httpGet.httpHeaders | HTTPHeader[]**

自定义请求头，是一个数组，每个头包括：name 和 value



**.httpGet.httpHeaders.name | string**

头字段名称（如 "Content-Type"），输出时会标准化（大小写不敏感）。



**.httpGet.httpHeaders.value | string**

头字段值。



**.httpGet.path | string**

HTTP 服务器上的访问路径。



**.httpGet.port | IntOrString**

端口号或名称，范围为 1-65535，或 IANA 服务名称。



**.httpGet.scheme | string**

连接方案，默认是 HTTP（可设置为 HTTPS）。



##### sleep

**.lifecycle.postStart.sleep | SleepAction**

让容器休眠一段时间。



**.sleep.seconds | integer**

休眠的秒数（整数）。



##### tcpSocket

已弃用，不支持作为生命周期钩子使用。



#### preStop

**.lifecycle.preStop| ExecAction**

容器在终止前立即执行 **preStop 钩子**，运行自定义操作，从而实现优雅的关闭和清理。

容器是崩溃或意外退出则不会调用 **preStop 钩子**。



无论 `preStop` 钩子执行成功或失败，**均不会直接影响 Pod 的最终阶段（`Succeeded`/`Failed`）**。Pod 的终止状态仅由**容器主进程的退出码**决定。



详细过程查看 **Pod 生命周期中 Pod 终止**部分。



### livenessProbe

**containers.livenessProbe | Probe**

livenessProbe 是 Kubernetes 中的一种容器探针，用于周期性地检**查容器是否还在正常运行**。如果探针失败，容器会被重启，以尝试恢复服务。

一旦 Pod 被创建，livenessProbe 的配置就不能被修改了。如果需要更改，您必须删除并重新创建 Pod。



**LivenessProbe** 支持 **exec**、**httpGet**、**tcpSocket** 和 **grpc** 四种健康检查机制。此处仅介绍 **tcpSocket** 和 **grpc** 这两种检查方式。



#### tcpSocket

**.livenessProbe.tcpSocket | TCPSocketAction**

TCPSocketAction 用于通过尝试连接到容器的指定 TCP 端口来检查容器是否健康。这是一种简单的网络连接检查，不涉及 HTTP 或其他协议。

它会尝试建立 TCP 连接，如果连接成功（TCP 三次握手完成），则探针视为成功；否则（如端口不可用或连接超时），探针失败。

```yaml
livenessProbe:
  tcpSocket:
    host: 127.0.0.1
    port: https       # <------ 这里也可以写成 443
```



**.tcpSocket.host | string**

指定要连接的主机名，默认是 Pod 的 IP 地址。



**.tcpSocket.port | IntOrString**

端口号或名称，必须在 1 到 65535 的范围内。如果是名称，必须是有效的 IANA 服务名称（例如 "http" 或 "ssh"）。



#### grpc

**.livenessProbe.grpc | GRPCAction**

GRPCAction 用于对 gRPC 服务进行健康检查。它会发送一个 gRPC Health Check 请求到指定的端口和服务名，以验证 gRPC 服务是否正常运行。这是一种针对 gRPC 协议的专用探针，常用于微服务架构。

如果服务响应健康状态，探针成功；否则，探针失败。gRPC 健康检查通常返回一个状态码，表示服务是否可用。

```yaml
livenessProbe:
  grpc:
    port: 50051    # <------ 仅能使用整型
    service: my-service
```



**.grpc.port | integer**

gRPC 服务的端口号，必须在 1 到 65535 的范围内。



**.grpc.service | string**

gRPC 服务名称，用于 HealthCheckRequest。如果未指定，Kubernetes 会使用 gRPC 的默认行为



#### other

**.livenessProbe.failureThreshold | integer**

指定**探针连续失败的最大次数**，只有达到此次数才认为**探针整体失败**，从而**触发容器重启**。这可以防止因一次**临时故障**（如网络波动）而立即重启容器。



**默认值**为 3（意思是连续失败 3 次后才失败），最小值为 1。



**.livenessProbe.initialDelaySeconds | integer**

容器启动后，延迟多少秒才开始执行 livenessProbe 检查。这允许容器有时间初始化和启动服务，避免在应用还未准备好时就进行检查。

无默认值，需要手动设置，根据应用启动时间设置（如 15 或 30 秒）。如果未设置则会**在容器启动后立即开始执行探针检查**。



**.livenessProbe.periodSeconds | integer**

定义探针执行的间隔时间（单位：秒），默认值是 10 秒，最小值是 1 秒。



**.livenessProbe.successThreshold | integer**

指定探针连续成功的最小次数后，才认为探针从失败状态恢复为成功。对于 livenessProbe 和 startupProbe，必须设置为 1（不能更改）。



**.livenessProbe.terminationGracePeriodSeconds | integer**

当探针失败导致 Pod 需要终止时，指定 Pod 优雅关闭的宽限期（单位：秒）。在这个时间内，Pod 会先收到终止信号，允许进程清理资源（如关闭数据库连接）；如果超时，会强制杀死进程。如果未设置，将使用 Pod spec 中的 terminationGracePeriodSeconds。

无**默认值**（如果未设置，则使用 Pod 级别的值），值为 0 表示立即强制停止。



**.livenessProbe.timeoutSeconds | integer**

指定每次探针执行的超时时间（单位：秒）。如果探针在这一时间内未完成（例如，HTTP 请求超时），则视为失败。

默认值为 1 秒。最小值为 1 秒。



### startupProbe

**containers.startupProbe | Probe**

startupProbe 用于检查容器是否已成功启动，尤其适合启动过程较长的应用（如需要加载大量数据或初始化复杂服务的容器）。它会在容器启动后立即运行，直到探针成功为止。一旦成功，Kubernetes 会停止运行 startupProbe，并开始执行其他探针（如 livenessProbe 和 readinessProbe）。

如果 startupProbe 失败，Kubernetes 会重启容器，但它不会影响 Pod 的就绪状态（readiness）。



### readinessProbe

**containers.readinessProbe| Probe**

readinessProbe 用于检查容器是否已准备好处理流量。如果探针成功，Pod 会被添加到 Kubernetes Service 的端点列表中（即可以接收流量）；如果失败，Pod 会从端点列表中移除，从而防止向不健康的 Pod 发送请求。

它不影响容器的重启，只影响流量路由。这有助于实现“灰度发布”或保护应用免受过载。



### resizePolicy

**containers.resizePolicy | ContainerResizePolicy[]**

在 Pod 运行时动态调整 CPU 和 Memory 资源限制，以适应不同应用场景，通过设置 `resizePolicy` 来控制资源调整后的行为（如自动重启容器或不重启）。

```
resizePolicy:
  - resourceNames: cpu
    restartPolicy: NotRequired
  - resourceNames: memory
    restartPolicy: Always
```



**.resizePolicy.resourceNames | string**

资源调整策略适用的资源名称，支持的值包括：`cpu`（CPU资源）和 `memory`（内存资源）。



**.resizePolicy.restartPolicy | string**

当指定的资源（如CPU或内存）被调整时，应用的容器重启策略。如果未指定，默认值为 `NotRequired`，意思是容器不需要强制重启（即调整资源后可以继续运行，而不中断服务）。其他可能的策略值可能取决于具体的系统（如 `Always` 或 `OnFailure`）。



### resources

**containers.resources | ResourceRequirements**

resources 用于指定容器所需的计算资源（如 CPU 和内存）和其他外部资源（如 GPU），以帮助 Kubernetes 调度器（Scheduler）合理分配节点资源。

```
resources:
  claims:  # 假设在实验性字段中使用
  - name: "my-gpu-claim"
    request: "1"  # 请求 1 个 GPU
  limits:
    cpu: 1
    memory: "200Mi"
  requests:
    cpu: 0.5
    memory: "100Mi"
```



**.resources.claims | ResourceClaim[]**

claims 允许 Pod 声明对特定资源的依赖，从而让 Kubernetes 调度器确保这些资源可用。

例如，如果一个容器需要特定的存储或硬件（如 GPU），claims 可以确保 Pod 只被调度到拥有这些资源的节点。



**.resources.claims.name | string**

声明的名称，用于标识这个资源声明。



**.resources.claims.request | string**

指定请求的具体资源类型或数量，例如存储大小。



**.resources.limits | object**

用于定义容器所需的最小资源量。这表示容器至少需要这些资源来运行。Kubernetes 会确保在调度 Pod 时，节点上有足够的可用资源来满足 `requests`。



**.resources.requests | object**

用于定义容器可使用的最大资源量。这表示容器绝不会超过这些限制。如果容器尝试使用超过 `limits` 的资源，Kubernetes 会强制限制它（例如，对 CPU 进行节流；对内存，可能会导致容器被杀死）。



### SecurityContext

**containers.SecurityContext | SecurityContext**

SecurityContext 是 Kubernetes 中的一个重要概念，用于定义容器运行时的安全选项。它允许您指定容器在运行时所需的权限和限制，例如用户 ID、组 ID、特权模式、文件系统权限等安全相关设置。



**.SecurityContext.runAsUser | integer**

指定容器进程运行的用户 ID。



**.SecurityContext.runAsGroup | integer**

指定容器进程运行的组 ID。



**.SecurityContext.privileged | boolean**

是否以特权模式运行（通常不推荐，用于需要高权限的场景）。



**.SecurityContext.capabilities | Capabilities**

添加或删除容器的 Linux 能力（如 CAP_NET_ADMIN）。



**.SecurityContext.seLinuxOptions | SELinuxOptions**

设置 SELinux 相关的安全上下文。



### stdin

**containers.stdin | boolean**

- **描述**：此字段决定容器运行时是否为标准输入 (stdin) 分配缓冲区。如果未设置此字段，容器从 stdin 读取时将总是立即返回 EOF（文件结束信号）。这意味着容器无法从 stdin 接收输入。
- **默认值**：false。



### stdinOnce

**containers.stdinOnce | boolean**

- **描述**：此字段决定容器运行时是否在第一次连接（attach）后关闭 stdin 通道。如果 stdin 设置为 true，stdin 流将保持打开状态，支持多次连接。如果 stdinOnce 设置为 true，则 stdin 在容器启动时打开，并在第一个客户端连接后接受数据，直到客户端断开连接，此时 stdin 将关闭并保持关闭状态，直到容器重启。如果设置为 false，容器进程从 stdin 读取时将永远不会收到 EOF。
- **默认值**：false。



### terminationMessagePath

**containers.terminationMessagePath | string**

- **描述**：可选字段，指定容器终止消息将被写入的文件路径，该文件会挂载到容器的文件系统中。消息内容通常是简短的最终状态信息，例如断言失败的消息。如果消息超过 4096 字节，节点会截断它；所有容器的总消息长度限制为 12KB。
- **默认值**：/dev/termination-log。



### terminationMessagePolicy

**containers.terminationMessagePolicy | string**

- **描述**：此字段指定如何填充容器的终止消息。"File" 选项会使用 terminationMessagePath 文件的内容来填充消息，无论容器是成功还是失败退出。"FallbackToLogsOnError" 选项在终止消息文件为空且容器以错误退出时，会使用容器的最后一部分日志输出作为消息。日志输出限制为 2048 字节或 80 行（以较小者为准）。
- **默认值**：File。



### tty

**containers.tty | boolean**

- **描述**：此字段决定容器是否为其分配一个终端 (TTY)。如果启用，还需要 stdin 设置为 true。TTY 用于支持交互式 shell 或命令行界面。
- **默认值**：false。



### volumeDevices

**containers.volumeDevices | VolumeDevice[]**

在容器中挂载块设备（如磁盘或分区）。这些设备通常与Pod中的PersistentVolumeClaim（PVC）关联。



**.volumeDevices.devicePath | string**

指定设备在容器内部的挂载路径。例如，如果设置为 `/dev/sda`，则表示将设备映射到容器的 `/dev/sda` 路径。



**.volumeDevices.name | string**

必须与Pod中定义的PersistentVolumeClaim的名称匹配。例如，如果Pod有一个名为 `my-pvc` 的PVC，则这里的name应设置为 `my-pvc`。



## ephemeral

**ephemeralContainers | EphemeralContainer[]**

临时容器



## initContainers

**initContainers | Container[]**

在 Kubernetes 中，`initContainers` 是一个数组字段，用于定义 Pod 中的初始化容器。这些容器会在 Pod 的正常容器（main containers）启动之前，按顺序执行。它们常用于执行一些预先准备的工作，例如下载依赖文件、配置环境或初始化数据库。

**限制和不支持的功能**：初始化容器不支持以下功能：

- **生命周期动作 (Lifecycle actions)**：如容器启动或停止时的钩子函数。
- **探针 (Probes)**：包括就绪探针 (Readiness probes)、存活探针 (Liveness probes) 和启动探针 (Startup probes)。这些探针通常用于正常容器以监控其健康状态。



## dnsConfig

**dnsConfig | PodDNSConfig**

PodDNSConfig 用于指定 Pod 的 DNS 参数。这些参数会与基于 DNSPolicy 生成的 DNS 配置合并。DNSPolicy 是 Kubernetes 默认的 DNS 策略（如 ClusterFirst），PodDNSConfig 可以自定义或扩展这些设置，从而影响 Pod 如何解析域名。



**dnsConfig.nameservers | string[]**

这是一个 DNS 名称服务器 IP 地址的列表。例如，["8.8.8.8", "8.8.4.4"]。用于自定义 Pod 使用的 DNS 服务器，比如使用外部的公共 DNS 服务。这不会替换基础的 DNS 服务器，而是进行追加。



**dnsConfig.options | PodDNSConfigOption[]**

这是一个数组，每个元素是一个对象，包含 `name` 和 `value` 字段，用于指定 DNS 解析器的特定选项。



每个选项本质上是针对 DNS 解析器的系统级配置。具体到您的示例：

```
options:
  name: "ndots"
  value: "1"
```

这是一个常见的 DNS 选项，用于控制主机名中的点号（dots）数量如何影响解析行为。在 DNS 解析中，如果一个主机名中的点号少于或等于 ndots 的值，解析器会先尝试使用搜索域（searches）来补充域名。



**dnsConfig.options.name | string**

DNS 解析器选项的名称，必填。例如，"ndots" 或 "timeout"。



**dnsConfig.options.value | string**

DNS 解析器选项的值。例如，对于 name 为 "ndots"，value 可以是 "1"。



**dnsConfig.searches | string[]**

这是一个 DNS 搜索域的列表。例如，["example.com", "internal.net"]。

假设您的配置中包含 `searches: ["example.com"]`，并且 Pod 要解析主机名 "app"：

- Kubernetes 会先尝试解析 "app.example.com"。
- 如果失败，它可能会尝试其他搜索域（如果有多个），或者回退到默认行为。



### dnsPolicy

**dnsPolicy | string**

`dnsPolicy` 是 Pod 规范（Pod spec）中的一个字段，用于设置 Pod 的 DNS（域名解析）策略。它决定了 Pod 如何解析域名。

**默认值**：`"ClusterFirst"`。这表示 Pod 会先尝试使用集群内部的 DNS 服务器来解析域名。如果失败，则回退到其他配置。

**有效值**：以下是可用的选项及其含义：

- **`"ClusterFirst"`**（默认）：Pod 使用集群的 DNS 服务器进行域名解析。
- **`"ClusterFirstWithHostNet"`**：类似于 `"ClusterFirst"`，但专门设计用于与 `hostNetwork: true` 一起使用（即 Pod 使用宿主机的网络）。如果您的 Pod 配置了 `hostNetwork`，必须显式设置为这个值，才能正确合并 DNS 选项。
- **`"Default"`**：Pod 使用宿主机的 DNS 配置，而不使用集群的 DNS 服务器。这适合需要与宿主机网络完全集成的场景。
- **`"None"`**：Pod 不使用任何预设的 DNS 策略。您需要手动通过 `dnsConfig` 字段指定完整的 DNS 配置。这提供最大的灵活性，但也需要额外的配置工作。



## enableServiceLinks 

**enableServiceLinks | boolean**

这个选项用于控制是否将服务（Service）的信息注入到 Pod 的环境变量中。具体来说，它会以类似于 Docker links 的语法方式注入服务信息，例如服务名称、IP 地址等。



## hostAliases

**hostAliases | HostAlias[]**

用于指定一组主机和 IP 地址，这些信息将被注入到 Pod 的 `/etc/hosts` 文件中。





**hostAliases.hostname | string[]**

指定与特定 IP 地址相关联的主机名列表。例如，如果您指定了一个 IP，您可以为它添加多个别名。



**hostAliases.ip | string**

指定主机文件条目的 IP 地址。



### hostIPC

**hostIPC | boolean**

决定是否使用宿主机的 IPC（进程间通信）命名空间。默认值为 false（不使用宿主机的 IPC 命名空间）。

如果设置为 true，Pod 将共享宿主机的 IPC 资源（如消息队列、共享内存），这在需要与宿主机或其他 Pod 进行高效通信时很有用。但这可能会增加安全风险，因为它打破了 Pod 的隔离。



## hostNetwork

**hostNetwork | boolean**

决定是否使用宿主机的网络命名空间。这意味着 Pod 将直接使用宿主机的网络接口、IP 和端口。默认值为 false	（不使用宿主机的网络命名空间）。



## hostPID

**hostNetwork | boolean**

决定是否使用宿主机的 PID（进程 ID）命名空间。默认值是 false（不使用宿主机的 PID 命名空间）。

如果设置为 true，Pod 中的进程将能够看到宿主机上的所有进程 ID。这在需要监控或交互宿主机进程时有用，但会降低隔离性，增加安全风险。



## hostUsers

**hostNetwork | boolean**

决定是否使用宿主机的用户命名空间。默认值是 true（使用宿主机的用户命名空间）。

如果设置为 true，Pod 将运行在宿主机的用户命名空间中，这允许 Pod 使用某些宿主机特有的功能（如加载内核模块）。如果设置为 false，Kubernetes 会为 Pod 创建一个新的用户命名空间，这有助于提升安全性，例如即使 Pod 以 root 身份运行，也不会获得宿主机的实际 root 权限，从而缓解容器逃逸风险。



## hostname

**hostNetwork | string**

用于指定 Pod 的主机名。如果未指定，Kubernetes 会为 Pod 分配一个系统定义的主机名（通常基于 Pod 的名称）。



## imagePullSecrets 

**imagePullSecrets | LocalObjectReference[]**

`imagePullSecrets` 是一个可选的数组字段，用于在 Kubernetes PodSpec 中指定一组 secrets。这些 secrets 用于拉取 Pod 中使用的容器镜像。如果您设置了这个字段，Kubernetes 会将这些 secrets 传递给镜像拉取器（puller），以帮助私有仓库或其他需要认证的镜像源进行身份验证。



**imagePullSecrets.name | string**

这是对引用的对象的名称，它指定了要引用的 secrets 的名称。



## nodeName

**nodeName | string**

`nodeName` 是一个字符串类型字段，用于指定Pod已经被调度到的节点名称。如果该字段为空，则表示Pod是待调度状态，将由Kubernetes集群中指定的调度器（通过`schedulerName`字段定义）来处理调度。一旦`nodeName` 被设置，目标节点的kubelet（Kubernetes的节点代理）将负责该Pod的整个生命周期，包括启动、监控和终止。

虽然您可以手动设置`nodeName` 来强制Pod运行在特定节点，但Kubernetes官方文档强烈建议不要这样使用。这是因为`nodeName` 不是设计用于表达调度偏好，而是用于描述Pod已经绑定的节点。如果您想将Pod调度到特定节点，应该使用其他机制（如`nodeSelector` 或 `Node Affinity`），以避免手动干预导致的调度问题。



## nodeSelector

nodeSelector | object

`nodeSelector` 是一个对象类型字段，用于定义一个标签选择器（selector），它必须匹配节点的标签，Pod才能被调度到该节点。这是一种简单的节点选择机制，基于键-值对的标签匹配，确保Pod只运行在符合条件的节点上。





