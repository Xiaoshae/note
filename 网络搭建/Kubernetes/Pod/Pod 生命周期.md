# Pod 生命周期

Pod 遵循预定义的生命周期，从 **Pending** 阶段开始。如果至少有一个主要容器正常启动，则进入 **Running** 阶段。随后，取决于 Pod 中是否有容器以失败状态结束，而进入 **Succeeded** 或 **Failed** 阶段。

Pod 被认为是相对临时性（而非长期存在）的实体。Pod 会被创建、赋予一个唯一的 **ID（UID）**，并被调度到节点，并在终止（根据重启策略）或删除之前一直运行在该节点上。如果一个节点失败，调度到该节点的 Pod 也会在给定超时期限结束后被删除。



在 Pod 运行时，**Kubernetes 的组件 kubelet**（负责在节点上管理容器）可以自动重启容器，以应对某些故障场景。例如，如果容器崩溃或出现错误，**kubelet 会尝试重启它来恢复正常运行**。同时，**Kubernetes 会监控 Pod 内部各个容器的状态**，并根据这些状态决定需要采取什么行动来让 Pod 恢复健康（如重启容器或标记 Pod 为失败）。

**Pod 不是永久的，它有开始、运行和结束的生命周期**。一旦 Pod 被创建，它会在指定的节点上运行，直到它正常停止、被手动终止，或者遇到不可恢复的错误。



在 Kubernetes 的 API 中，Pod 对象分为两个主要部分：**规约 (Spec)** 和 **实际状态 (Status)**。

-  **规约 (Spec)** 是 Pod 的期望状态，包括定义的容器、资源需求等配置。
-  **实际状态 (Status)** 是 Pod 的当前真实状态，包括 Pod 的运行状况。

此外，**实际状态 (Status)** 部分包含一组 **Pod 状况 (Conditions)**，这些是 Kubernetes 用来描述 Pod 健康状态的指标，例如 **Ready**（就绪）、**Scheduled**（已调度）等状况，能帮助 Kubernetes 和用户判断 Pod 是否正常运行。

如果应用有特殊需求，可以向 Pod 注入自定义的就绪态信息，比如添加额外的检查条件，来更精确地定义 Pod 何时被视为 **就绪**。



## 调度和绑定

在 Kubernetes 中，**Pod 在其整个生命周期中，只被调度一次**。调度是由 Kubernetes 的调度器根据节点的资源可用性、亲和性规则等因素选择合适的节点，然后将 Pod 分配（绑定）到具体的节点上。

一旦 Pod 被调度到某个节点，Kubernetes 就会在那里尝试启动并运行 Pod。Pod 会一直运行在那里，直到 **Pod 正常停止**（例如，任务完成）、**被手动终止**，或者在启动过程中出现问题（如节点崩溃），此时这个特定的 Pod 可能无法启动，且 Kubernetes 不会自动尝试调度它到其他节点，除非配置了相关的策略。

**调度是不可逆的**，意味着 Pod 是绑定到节点的，如果节点故障，Pod 不会自动迁移到其他节点（不像一些高级资源如 StatefulSet 或 Deployment 那样）。



调度就绪态（**延迟调度**），这是一种机制，用于延迟Pod的调度，直到某些条件被满足。例如，设置**“调度门控”（Scheduling Gates)**，让Pod在所有预定义的条件都移除后再进行调度。 

假设定义了一组Pod，但希望这些Pod只在某些外部条件准备好后才启动调度。比如，可能有一个依赖关系：只有当所有相关的Pod（如**数据库Pod**）都创建完成时，才允许当前Pod调度。这可以防止Pod过早启动而失败。



## Pod 故障恢复

如果Pod中的某个容器出现故障（如崩溃或错误），Kubernetes 可能会尝试直接重启那个具体的容器（ 有关细节参阅 Pod 如何处理容器问题），而不是重启整个Pod。



在 Kubernetes 集群中，以下情况可能导致 Pod 出现不可恢复的故障：

- **节点失效**：如果 Pod 被调度到一个节点（Node），但这个节点后来失效（例如，节点崩溃或网络问题），Kubernetes会将Pod标记为不健康。
- **节点问题**：如果节点资源耗尽（比如CPU或内存不足）或节点需要维护，Pod可能会被“驱逐”（Evicted），意思是它无法继续在那个节点上运行。



当发生不可恢复的故障时，Kubernetes 会**自动删除故障 Pod**，其行为与执行 `kubectl delete pod` 命令完全一致，将故障 Pod 从集群中彻底移除。

**如果存在相关控制器（如 Deployment、StatefulSet 等）**，系统会自动创建新的 Pod 来替代被删除的故障 Pod，确保服务持续可用。

**如果没有配置相应的控制器或自动修复机制**，则需要管理员手动介入，重新创建 Pod 以恢复服务。



在 Kubernetes 中，**每个 Pod 都由其唯一标识符（UID）定义**，且一旦创建后**不会被重新调度到其他节点**。如果某个 Pod 需要被替换，会**创建一个全新的 Pod 实例**。这个新 Pod 几乎完全相同（可以有相同的配置和名称），但它会有一个不同的 **UID**（**.metadata.uid**）。Kubernetes 不保证新Pod 会被调度到与旧Pod 相同的节点，调度取决于当前集群的资源可用性和策略。



如果某个对象（如存储卷）声称其生命周期与某个 **Pod** 相同，这个对象只在那个 **Pod** 存活期间存在，一旦那个 **Pod** 被删除，这个对象也会被一并删除。

在 Kubernetes 中的每个 **Pod** 都有一个唯一的标识符（**UID**）。即使你创建了一个看起来一模一样的 **Pod**（相同的配置、名称等），它实际上是一个新的 **Pod**，具有不同的 **UID**。因此，如果对象绑定到原来的 **Pod** 上，新创建的 **Pod** 不会继承这个对象。

如果 **Pod** 因为任何原因被删除（例如，**Pod** 崩溃、被手动删除或资源不足），那么与其绑定的对象也会被删除。同时，如果系统自动创建一个新的 **Pod** 来替换它（例如，通过 **ReplicaSet** 或 **Deployment**），这个对象不会被保留，而是会为新的 **Pod** 重新创建。



![一个包含文件拉取程序 Sidecar（边车） 和 Web 服务器的多容器 Pod。此 Pod 使用临时 emptyDir 卷作为容器之间的共享存储。](./images/Pod%20%E7%94%9F%E5%91%BD%E5%91%A8%E6%9C%9F.assets/pod.svg)

这是一个多容器 Pod，包含文件拉取程序 **Sidecar**（边车）和 Web 服务器，并使用临时 **emptyDir** 卷作为容器之间的共享存储。





## Pod 阶段

Pod 的状态（Status）包括一个关键字段叫 Phase（阶段），这是一个简单的高层概述，用于表示 Pod 当前所处的状态。

Kubernetes 只定义了主要的 Phase 值，除此之外没有其他 Phase 值。以下是主要的 Phase 值及其含义：

| 取值                | 描述                                                         |
| :------------------ | :----------------------------------------------------------- |
| `Pending`（悬决）   | Pod 已被 Kubernetes 系统接受，但有一个或者多个容器尚未创建亦未运行。此阶段包括等待 Pod 被调度的时间和通过网络下载镜像的时间。 |
| `Running`（运行中） | Pod 已经绑定到了某个节点，Pod 中所有的容器都已被创建。至少有一个容器仍在运行，或者正处于启动或重启状态。 |
| `Succeeded`（成功） | Pod 中的所有容器都已成功结束，并且不会再重启。               |
| `Failed`（失败）    | Pod 中的所有容器都已终止，并且至少有一个容器是因为失败终止。也就是说，容器以非 0 状态退出或者被系统终止，且未被设置为自动重启。 |
| `Unknown`（未知）   | 因为某些原因无法取得 Pod 的状态。这种情况通常是因为与 Pod 所在主机通信失败。 |

注意：不要将 **Phase** 与 kubectl 命令中的 **Status** 字段混淆。**Status** 是 kubectl 为用户显示的直观信息（如 **"CrashLoopBackOff"** 或 **"Terminating"**），而 **Phase** 是 Kubernetes API 中的正式部分。



**CrashLoopBackOff** 不是一个正式的 Phase，而是在 kubectl 输出中出现的状态。它表示 Pod 反复尝试启动但失败了，导致容器不断崩溃并重试。

```
NAMESPACE               NAME               READY   STATUS             RESTARTS   AGE
alessandras-namespace   alessandras-pod    0/1     CrashLoopBackOff   200        2d9h
```



当用户使用 kubectl delete（或其他自动方法）触发 Pod 的删除时，会发送 **SIGTERM** 信号给 Pod 中的容器，通知它们开始优雅退出（例如，保存状态、关闭资源），同时宽限期开始计时（默认 30 秒）。在这个阶段，Pod 的状态显示为 **“Terminating”**，容器会尝试在宽限期内完成退出。如果容器在宽限期内正常退出，Pod 的 Phase 会更新为 **“Succeeded”** 或 **“Failed”**（取决于容器的退出代码）。**如果容器在宽限期内没有正常退出，会发送 *SIGKILL* 信号强制终止容器，并将 Pod 的 Phase 更新为 “*Failed*”。**一旦宽限期结束（或容器提前退出），kubelet 会确认 Pod 已终止，然后通知 API 服务器完全移除 Pod 的记录。



以下两种情况，kubelet 会跳过这个标准流程，直接删除 Pod：

- **静态 Pod（Static Pod）**：直接由 kubelet 在节点上管理的 Pod，而不是通过 Kubernetes API 服务器创建和管理的。它们通常用于系统级组件，例如 kube-proxy、kube-dns 等核心服务。
- **没有 Finalizer 的且强制终止的 Pod**：
  - **Finalizer** 是 Kubernetes 中的一个机制，用于确保在删除资源（如 Pod）之前，执行某些必要的清理操作。
  - **强制终止**通常是通过命令如 `kubectl delete pod <pod-name> --force` 触发的。这会忽略正常的宽限期，直接尝试快速删除 Pod。



如果某节点死掉或者与集群中其他节点失联，Kubernetes 会实施一种策略，将失去的节点上运行的所有 Pod 的 `phase` 设置为 `Failed`。



## 容器状态

Kubernetes会监控和管理Pod（一种可运行的容器组）中的每个容器状态，就像它监控Pod的整体生命周期一样。

容器的状态主要有三种：**Waiting（等待）**、**Running（运行中）** 和 **Terminated（已终止）**。您可以使用命令 `kubectl describe pod <pod名称>` 来查看Pod中每个容器的状态及其详细信息。



**Waiting（等待）**：容器还没有完全启动，还在准备阶段。例如，它可能正在从镜像仓库拉取**容器镜像**，或者在应用一些配置（如**Secret 数据**）。

**Running（运行中）**：容器已经成功启动并正常运行中。如果配置了**postStart 回调**（容器启动后的钩子函数），它已经执行完成。

**Terminated（已终止）**：容器已经结束运行，可能因为正常完成任务、超时、错误或其他原因。如果配置了**preStop 回调**（容器停止前的钩子函数），它会在容器进入此状态前执行。





## 容器问题

在 Pod 的配置文件（spec）中，有一个 **restartPolicy** 字段，它定义了 Kubernetes 如何响应容器因错误（如崩溃或退出）而停止的情况。

这个策略的默认值是 **Always**，并且支持以下选项：

- **Always**：只要容器终止（不管原因），就自动重启。
- **OnFailure**：只在容器因错误退出（例如退出码非零）时重启。如果容器正常退出，则不重启。
- **Never**：容器终止后，不会自动重启。

Pod 的 **restartPolicy** 字段主要影响 Pod 中的应用容器和常规 **Init 容器**（用于初始化的容器）。然而，对于 **Sidecar 容器**（在文本中定义为 initContainers 中的一个条目），它会忽略 Pod 级别的 **restartPolicy**，并强制使用容器级别的 **"Always"** 策略。另外，如果 **Init 容器** 因错误退出，而 Pod 的 **restartPolicy** 设置为 **"OnFailure"** 或 **"Always"**，则 Kubernetes 的 kubelet 组件会尝试重启该 **Init 容器**。



处理容器崩溃的策略：

- **初始崩溃**：容器第一次崩溃时，Kubernetes会根据restartPolicy立即尝试重启。
- **反复崩溃**：如果容器继续崩溃，Kubernetes会采用“**指数级回退延迟**”机制。
- **回退重置**：如果容器成功运行一段时间（如10分钟），系统会重置延迟机制，下次崩溃会被视为新问题，从初始延迟开始。



Kubernetes 会使用一个 **指数级回退延迟机制** 来控制重启间隔。这是一种保护机制，防止容器反复崩溃导致系统负载过高。延迟的计算方式，**初始延迟** 从 10 秒 开始，**增长方式** 是每次重启失败后，延迟时间会翻倍（例如，第一次 10 秒，第二次 20 秒，第三次 40 秒，依此类推），**最大延迟**上限为 300 秒（5 分钟）。一旦容器成功运行 10 分钟 以上，延迟计时器会重置回初始值。

在 Kubernetes 中，一旦容器重启延迟达到最大值（默认 300 秒），Kubelet（Kubernetes 在节点上的代理）会**继续尝试重启容器**，但**不会再增加重启间隔**。



**CrashLoopBackOff** 状态：这是一个 **Pod** 的状态，表示容器正处于崩溃循环中（反复失败并重启），系统会等待延迟结束后再尝试。这种状态通常在使用命令如 **kubectl describe pod** 时看到，是一个**常见的警告信号**。



**v1.33 Alpha**

启用 **Kubernetes v1.33 Alpha** 特性开关 `ReduceDefaultCrashLoopBackOffDecay` 后，集群中容器启动重试的初始延迟将从 **10 秒** 减少到 **1 秒**，之后每次重启延迟时间按 2 倍指数增长，直到达到最大延迟 **60 秒**（之前为 **300 秒**，即 5 分钟）。



**v1.32 Alpha**

启用 **Kubernetes v1.32 Alpha** 特性门控 `KubeletCrashLoopBackOffMax` 后， 你可以重新配置容器启动重试之间的最大延迟，默认值为 **300 秒**（即 5 分钟）。此配置针对每个节点通过 kubelet 配置进行设置。 在 kubelet 配置中， 在 crashLoopBackOff 下设置 **maxContainerRestartPeriod** 字段，取值范围在 "1s" 到 "300s" 之间。

如上文容器重启策略所述，该节点上的延迟仍将从 **10 秒** 开始，并在每次重启后以指数方式增加 2 倍，但现在其上限将被限制为你所配置的最大值。如果你配置的 **maxContainerRestartPeriod** 小于默认初始值 **10 秒**， 则初始延迟将被设置为配置的最大值。



如果您同时启用 **ReduceDefaultCrashLoopBackOffDecay**，集群的默认延迟会立即变为 **1 秒**（初始）和 **60 秒**（最大）。

但是，**KubeletCrashLoopBackOffMax** 的节点级配置会覆盖这个集群默认值。换句话说，每个节点的自定义设置（如最大延迟为 **100 秒**）会优先于 **ReduceDefaultCrashLoopBackOffDecay** 设定的 **60 秒**。



参见以下 kubelet 配置示例：

```yaml
# 容器重启延迟将从 10 秒开始，每次重启增加 2 倍
# 最高达到 100 秒
kind: KubeletConfiguration
crashLoopBackOff:
    maxContainerRestartPeriod: "100s"
```

```yaml
# 容器重启之间的延迟将始终为 2 秒
kind: KubeletConfiguration
crashLoopBackOff:
    maxContainerRestartPeriod: "2s"
```



下列问题可以导致 `CrashLoopBackOff`：

- **应用程序错误**：容器里的应用代码有bug，导致它退出。
- **配置错误**：例如环境变量设置不对、配置文件丢失，或者外部资源（如数据库）不可用。
- **资源限制**：容器分配的CPU或内存不足，无法启动或运行。
- **健康检查失败**：Kubernetes使用“探针”（如存活探针或启动探针）来检查容器健康。如果容器没有在预期时间内启动服务，或者探针返回失败，系统会认为它崩溃并触发重启。



要调查 `CrashLoopBackOff` 问题的根本原因，用户可以：

1. **检查日志**：使用 `kubectl logs <pod名称>` 检查容器的日志。 这通常是诊断导致崩溃的问题的最直接方法。
2. **检查事件**：使用 `kubectl describe pod <pod名称>` 查看 Pod 的事件， 这可以提供有关配置或资源问题的提示。
3. **审查配置**：确保 Pod 配置正确无误，包括环境变量和挂载卷，并且所有必需的外部资源都可用。
4. **检查资源限制**： 确保容器被分配了足够的 CPU 和内存。有时，增加 Pod 定义中的资源可以解决问题。
5. **调试应用程序**：应用程序代码中可能存在错误或配置不当。 在本地或开发环境中运行此容器镜像有助于诊断应用程序的特定问题。



## Pod 状况

Pod 有一个 **Pod Status** 对象，**Pod Status** 对象包含一个数组，名为 **Pod Conditions**，这个数组用于记录 Pod 的各种“状况”（conditions）。

**Pod Conditions** 数组的每个元素是一个对象（object），由多个键值对（key-value pairs）组成，例如以下键值对：

| 字段名称             | 描述                                                         |
| :------------------- | :----------------------------------------------------------- |
| `type`               | Pod 状况的名称                                               |
| `status`             | 表明该状况是否适用，可能的取值有 "`True`"、"`False`" 或 "`Unknown`" |
| `lastProbeTime`      | 上次探测 Pod 状况时的时间戳                                  |
| `lastTransitionTime` | Pod 上次从一种状态转换到另一种状态时的时间戳                 |
| `reason`             | 机器可读的、驼峰编码（UpperCamelCase）的文字，表述上次状况变化的原因 |
| `message`            | 人类可读的消息，给出上次状态转换的详细信息                   |



对象中的 **type** 键值对包括以下关键字段：

- **PodScheduled**：表示 Pod 是否已经被调度到某个节点（Node）。如果为 True，意味着 Kubernetes 已经为这个 Pod 分配了一个运行节点。
- **PodReadyToStartContainers**：这是一个 Beta 特性，默认启用的功能。它表示 Pod 的“沙箱”（Sandbox，指 Pod 的运行环境）已经成功创建，并配置好了网络。这一步确保容器可以安全启动。
- **ContainersReady**：表示 Pod 中的所有容器都已经就绪。这意味着容器已经完成启动、加载配置，并准备好处理任务。
- **Initialized**：表示所有 Init 容器（初始化容器，用于在主容器启动前执行一些初始化任务）都已经成功完成。如果有 Init 容器，它们必须先运行完毕才能继续。
- **Ready**：表示 Pod 已经完全准备好，可以为请求提供服务。这通常意味着 Pod 可以正常工作，并且应该被添加到相关服务的负载均衡池中（例如，在一个服务中，Pod 会作为后端处理流量）。



在使用 **kubectl describe pod** 查看 Pod 的详细信息时，只会列出 **type** 和 **status** 键值对。

```
Conditions:
  Type                        Status
  PodReadyToStartContainers   True 
  Initialized                 True 
  Ready                       True 
  ContainersReady             True 
  PodScheduled                True 
```



### Pod 就绪态

在 Kubernetes 中，**Pod** 的**就绪态**表示该 Pod 是否已完全准备好，能够处理流量并加入服务（如 **Service**）的负载均衡池。默认情况下，Kubernetes 会根据内置条件（如所有容器就绪）来判断 Pod 的就绪状态。

从 **Kubernetes v1.29** 开始，Beta 特性 **"就绪态门控"（Readiness Gates）** 允许应用向 Pod 状态注入自定义条件。这样，Kubernetes 在评估 Pod 就绪状态时，不仅考虑内置条件，还考虑您自定义的信号或反馈。



在 Pod 的规约（**spec**）中设置 **readinessGates** 字段，**readinessGates** 是一个列表，包含一组自定义的条件类型（**conditionType**）。Kubernetes 会检查这些条件是否为 **True**，如果所有条件都满足，Pod 才会被标记为就绪。

如果 Kubernetes 在 Pod 的状态（**status.conditions**）中找不到某个自定义条件，它会默认该条件的状态为 **"False"**，从而使 Pod 不就绪。

Kubernetes 不会主动监控或评估这些自定义条件是否为 **True**，您（或您的应用、控制器）需要通过 Kubernetes API 手动更新 Pod 的 **status.conditions** 字段，将这些自定义条件的状态设置为 **"True"** 或 **"False"**。



这里是一个例子：

```yaml
kind: Pod
...
spec:
  readinessGates:
    - conditionType: "www.example.com/feature-1"
status:
  conditions:
    - type: Ready                              # 内置的 Pod 状况
      status: "False"
      lastProbeTime: null
      lastTransitionTime: 2018-01-01T00:00:00Z
    - type: "www.example.com/feature-1"        # 额外的 Pod 状况
      status: "False"
      lastProbeTime: null
      lastTransitionTime: 2018-01-01T00:00:00Z
  containerStatuses:
    - containerID: docker://abcd...
      ready: true
...
```



你不能直接用 **kubectl patch** 命令来修改 Kubernetes 对象的状态（**status.conditions**）。需要通过编程方式，调用 **Kubernetes API** 发送 PATCH 请求，来更新 Pod 的 **status.conditions** 字段。



### Pod 网络就绪

如果启用了 **PodReadyToStartContainersCondition** 特性门控（在 **Kubernetes 1.33** 版本中默认启用），则 **PodReadyToStartContainers** 状况会被添加到 Pod 的 status.conditions 字段中。

**PodReadyToStartContainers** 是一个 Kubernetes Pod 状态条件（Pod Condition），当运行时插件成功完成 **Pod 的沙箱创建和网络配置** 后， kubelet 会将该状况设置为 **True**。

当 **PodReadyToStartContainers** 状况设置为 **True** 后， Kubelet 可以开始拉取容器镜像和创建容器。



当 Kubelet 检测到 Pod 没有配置**网络的运行时沙箱**时，**PodReadyToStartContainers** 状况将被设置为 **False**。这种状况通常会发生在以下场景中：

- 在 Pod 生命周期的早期阶段，kubelet 还没有开始使用容器运行时为 Pod 设置沙箱时。

- 在 Pod 生命周期的末期阶段，Pod 的沙箱由于以下原因被销毁时：
  - 节点重启时（但 Pod 没有被驱逐）
  - 对于使用虚拟机进行隔离的容器运行时，Pod 沙箱虚拟机重启时，需要创建一个新的沙箱和全新的容器网络配置。



当一个 **Node** 重启时，Kubernetes 会通过 **Pod 驱逐策略（Eviction Policies）** 和 **节点健康检查** 等机制来决定是否驱逐 **Pod**。例如，如果节点重启迅速且资源充足，则 **Pod** 未被驱逐；但由于节点重启，**Pod** 的沙箱已销毁，这会导致 **PodReadyToStartContainers** 变为 False，进而 **Kubelet** 需要重新创建 **Sandbox** 和网络配置。



某些高级容器运行时（如 Kata Containers 或 gVisor）通过轻量级虚拟机 (VM) 运行容器，而非直接使用主机资源。这种方法比传统运行时（如 Docker）**安全性更高、隔离性更强**，因为每个 Pod 的容器在独立的 VM 环境中运行，不共享主机内核。Pod 的 Sandbox 基于 VM 实现。若 VM 因故障、节点重启或资源不足重启，Sandbox 将被销毁或重置。



**Init 容器**是 Pod 中的特殊容器，它会在主容器（即 Pod 的主要应用容器）启动之前运行。**它的主要作用**是执行一些先决条件任务，例如准备配置文件或初始化数据库等操作。

**Initialized** 是一个布尔状态（True 或 False），用于表示 Pod 的初始化过程是否完成。当 Init 容器成功运行后，该状态会被设为 **True**，表明 Pod 已准备好进入下一阶段（如启动主容器）。

**对于包含 Init 容器的 Pod**，Kubelet 会在 Pod 的沙箱创建和网络配置（PodReadyToStartContainers 为 True）后启动 Init 容器。**只有在 Init 容器成功完成后**，Kubelet 才会将 Initialized 设为 True，并开始启动主容器。

**对于不包含 Init 容器的 Pod**，Kubelet 会在 PodReadyToStartContainers 状态为 True 后，**直接**将 Initialized 设为 True（因为没有 Init 容器需要运行），并立即启动主容器。



## 探针

**探针（Probes）** 是 Kubernetes 中的一种功能，由 kubelet（Kubernetes 节点上的代理程序）定期对容器执行诊断检查。要执行诊断，kubelet 既可以在容器内执行代码，也可以发出一个网络请求。



**检查机制**，使用探针来检查容器有四种不同的方法。 每个探针都必须准确定义为这四种机制中的一种：

- `exec`：用于**在容器内执行指定命令**。如果该命令退出时返回码为 **0**，则认为诊断成功。

- `grpc`：**使用 gRPC 执行一个远程过程调用**。目标应该实现 gRPC 健康检查。如果响应的状态为 **"SERVING"**，则认为诊断成功。
- `httpGet`：**对容器的 IP 地址上指定端口和路径执行 HTTP GET 请求**。如果响应的状态码大于等于 **200** 且小于 **400**，则诊断被认为是成功的。
- `tcpSocket`：**对容器的 IP 地址上的指定端口执行 TCP 检查**。如果端口打开，则诊断被认为是成功的。如果远程系统（容器）在打开连接后立即将其关闭，这算作是健康的。



注意：**exec** 每次都会创建新进程，这可能增加 **CPU 负载**，尤其是在 **高密度 Pod**（容器组）环境中。如果您的集群有许多 **Pod**，并且 **initialDelaySeconds** 和 **periodSeconds** 设置较短，建议避免使用 **exec**，转而采用其他机制。



**探测结果**，每次探测都将获得以下三种结果之一：

- `Success`（成功）：容器通过了诊断。
- `Failure`（失败）：容器未通过诊断。
- `Unknown`（未知）：诊断失败，因此不会采取任何行动。



**探测类型**，**kubelet** 可以针对运行中的容器选择是否执行**以下三种探针**，以及**如何针对探测结果作出反应**：

- `livenessProbe`：**指示容器是否正在运行**。如果存活探针失败，则 **kubelet** 会杀死容器，并且容器将**根据其重启策略**决定未来。如果容器不提供存活探针，则默认状态为 **Success**。
- `readinessProbe`：**用于检查容器是否准备好处理请求**（例如，能否接受流量）。如果失败，**EndpointSlice 控制器**会从与该 Pod 匹配的 Service 的端点列表中移除该 Pod 的 IP 地址（即不让它接收流量）。**初始延迟之前的就绪态的状态值默认为 `Failure`**。如果容器不提供就绪态探针，则默认状态为 **Success**。
- `startupProbe`：**用于检查容器中的应用是否已经完全启动**。如果定义了这个探针，**其他探针（如 livenessProbe 和 readinessProbe）会在它成功前被禁用**。如果失败，**kubelet 会杀死容器，并根据重启策略重启它**。如果没有定义这个探针，则默认状态为 **Success**。



**初始延迟（Initial Delay）**：在 Pod 启动时，您可以配置一个参数 **initialDelaySeconds**，它指定了探针检查开始前的等待时间。例如，如果您设置 **initialDelaySeconds: 10**，表示 Pod 启动后，系统会等待 10 秒钟，才开始执行就绪探针的实际检查。

在这个初始延迟期结束之前，**Kubernetes 会假设 Pod 还没有准备好**，**就绪探针的状态会被自动视为 “Failure”**（失败），因此不会将它加入服务端点。这是一种默认的保护机制，确保 Pod 在完全启动并通过检查前，不会意外接收流量。



## 终止 Pod

当终止 Kubernetes 的 Pod 中运行的容器时，会先进行**体面终止（graceful termination）**，而不是直接**强制杀死**进程。这确保进程能够完成清理工作，如保存数据和关闭连接。



当您请求删除一个Pod 时，kubelet 先发送 **TERM**（又名 **SIGTERM**） 信号到每个容器中的主进程，以尝试停止 Pod 中的容器。 发送信号由容器运行时以异步方式处理，无法保证发送信号的顺序。如果超出体面终止限期，容器依然没有停止，会向所有剩余进程发送 **KILL** 信号，之后 Pod 就会被从**API 服务器**上移除。



终止容器的停止信号为容器镜像中的 **STOPSIGNAL** 指令定义的信号。如果镜像中未定义停止信号，容器运行时（如 containerd 和 CRI-O）会使用默认的 **SIGTERM** 信号来终止容器。

如果启用了 **ContainerStopSignals** 特性门控，你可以通过容器的**生命周期配置**自定义的停止信号。要自定义停止信号，必须设置 Pod 的 **spec.os.name** 字段。可用的信号列表取决于 Pod 调度到的操作系统。对于调度到 Windows 节点的 Pod，仅支持 **SIGTERM** 和 **SIGKILL** 信号。

以下是一个定义了自定义停止信号的 Pod 示例：

```yaml
spec:
  os:
    name: linux
  containers:
    - name: my-container
      image: container-image:latest
      lifecycle:
        stopSignal: SIGUSR1
```



### Pod 终止流程

使用 **kubectl** 工具手动删除某个特定的 Pod，而该 Pod 的体面终止限期是默认值（30 秒）。

通过 **kubectl delete** 删除某个 Pod 后，使用 **kubectl describe** 来查验正在删除的 Pod，该 Pod 会显示为 **"Terminating"** （正在终止）。 此时 **kubelet** 开始本地的 Pod 关闭过程。



1. 处理 preStop 回调

如果 Pod 中的一个容器定义了 **preStop 回调**且 Pod 规约中的 **terminationGracePeriodSeconds** 未设为 0，则 kubelet 会开始在容器内运行该回调逻辑。（默认的 **terminationGracePeriodSeconds** 设置为 30 秒）



2. 发送 TERM 信号

等待 **preStop 回调**完成后，kubelet 会触发容器运行时，发送 **TERM 信号**给每个容器中的进程 1，并等待容器停止。



3. 发送 SIGKILL 信号

如果超出终止宽限期限（默认为 30 秒），且 **Pod** 中仍有容器在运行，kubelet 会触发强制关闭过程。 然后，容器运行时会向 **Pod** 中所有容器内仍在运行的进程发送 **SIGKILL** 信号，强制停止 **Pod** 所有容器内仍在运行的进程。



4. Pod 转换到终止阶段

当 **kubelet** 发送 **TERM** 信号时，Pod 中的所有容器将在终止宽限期限内正常停止，或超出该期限后被 **SIGKILL** 信号强制停止。随后，**kubelet** 会根据容器的结束状态，将 Pod 转换为终止阶段（**Failed** 或 **Succeeded**）。



5. 删除 Pod 对象

API 服务器删除 Pod 的 API 对象，从任何客户端都无法再看到该对象。



终止宽限期限和 **terminationGracePeriodSeconds** 是同一个概念，这两个的值是相等的，而且**容器宽限时间**和 **preStop** 回调时间是共享的。

- 当触发 Pod 删除时，如果**该容器**存在 **preStop** 回调，首先执行 **preStop** 回调。假设该回调耗用 10 秒后，随即向**该容器**发送 **TERM** 信号，此时剩余终止宽限期为 20 秒。如果**该容器**在 20 秒内未正常退出，则会发送 **KILL** 信号强制终止**该容器**。
- 如果容器存在 **preStop** 回调，且该回调在耗尽 30 秒后仍未完成，则直接发送 **KILL** 信号强制停止该容器，跳过发送 **TERM** 信号。
- 如果容器没有 **preStop** 回调，则**该容器**独享 **30 秒的宽限期**。

**preStop** 回调是在容器内部以独立进程的方式运行的。它不是在 Kubernetes 外部执行，而是在容器的运行时环境中启动，作为一个额外的命令或脚本。当容器收到 **KILL** 信号时，**preStop** 回调的进程也会被强制停止。



无论 `preStop` 钩子执行成功或失败，**均不会直接影响 Pod 的最终阶段（`Succeeded`/`Failed`）**。Pod 的终止状态仅由**容器主进程的退出码**决定。



如果 Pod 定义了 **Sidecar** 容器，Kubernetes 会应用特殊的终止规则：**kubelet** 会先确保所有主容器完全终止，然后再终止 **Sidecar** 容器。**Sidecar** 容器的终止顺序是按照它们在 Pod 规约中定义的**相反顺序**进行的。

虽然 **kubelet** 会确保所有主容器完全终止后，才会向 **Sidecar** 容器发送 TERM 信号，但是两者的宽限时间是同时开始的。假设关闭所有主容器耗费 10 秒，则 **Sidecar** 容器的宽限时间只有 20 秒。如果 30 秒的宽限时间全部耗尽，就会发送 **KILL** 信号强制关闭所有主容器和 **Sidecar** 容器，且 **Sidecar** 容器会跳过 TERM 信号的发送。

- 如果您有多个容器，需要确保 **A** 容器在 **B** 容器关闭前完成某些操作，您可以用 **preStop** 在 **A** 容器中添加等待逻辑。
- 如果您的场景更适合通过 **Sidecar** 来管理依赖关系，您可以重构 Pod，将辅助容器定义为 **Sidecar**，从而利用 Kubernetes 的内置排序机制，而非手动使用 **preStop**。



Pod 的体面关闭时，ReplicaSet 和其他工作负载资源不再将关闭进程中的 Pod 视为合法的、能够提供服务的副本。



任何正在终止的 Pod 所对应的端点都不会立即从 **EndpointSlice** 中被删除，**EndpointSlice API** 会公开一个状态来指示其处于**终止状态**。 正在终止的端点始终将其 **ready 状态**设置为 false，因此负载均衡器不会将其用于常规流量。 正在终止的 Pod 会处理在开始终止前就已经建立连接的流量，部分应用程序还需要更进一步的体面终止逻辑（如排空和完成会话）。

如果需要排空**正在终止的 Pod**上的流量，可以将**serving 状况**作为实际的**就绪状态**。 你可以在教程**探索 Pod 及其端点的终止行为**中找到有关如何实现连接排空的更多详细信息。



### 强制终止 Pod

默认情况下，所有的删除操作都会附有 30 秒钟的宽限期限。 `kubectl delete` 命令支持 `--grace-period=<seconds>` 选项，允许你重载默认值， 设定自己希望的期限值。你必须同时额外设置 `--force` 参数才能发起强制删除请求。

```
kubectl delete pod <PodName> --grace-period=0 --force
```



在执行强制删除操作时，**API 服务器**不再等待来自 **kubelet** 的、关于 **Pod** 已经在原来运行的节点上终止执行的确认消息。**API 服务器**直接删除 **Pod** 对象，这样新的与之同名的 **Pod** 就可以被创建。 在节点侧，被设置为立即终止的 **Pod** 仍然会在被强行杀死之前获得一点点的宽限时间。



> 注意：在马上删除时，**不等待确认**正在运行的资源已被终止。这些资源可能会**无限期地继续** 在集群上运行。



如果你需要强制删除 StatefulSet 的 Pod， 请参阅从 StatefulSet 中删除 Pod 的任务文档。



### Pod 的垃圾收集

对于已失败的 Pod 而言，其对应的 API 对象会保留在集群的 API 服务器上，直到用户或控制器进程**显式地将其删除**。

**Pod 的垃圾收集器（PodGC）** 是控制平面的控制器，它会在 Pod 个数超出所配置的阈值（根据 kube-controller-manager 的 **terminated-pod-gc-threshold** 设置）时删除已终止的 Pod（阶段值为 Succeeded 或 Failed）。这一行为有助于避免随着时间推移不断创建和终止 Pod 而导致的资源泄露问题。



此外，PodGC 会清理满足以下任一条件的所有 Pod：

- 孤儿 Pod - 绑定到不再存在的节点，
- 计划外终止的 Pod
- 终止过程中的 Pod，绑定到有 **node.kubernetes.io/out-of-service** 污点的未就绪节点。



在清理 Pod 的过程中，如果这些 Pod 处于**非终止状态阶段**，**PodGC** 也会将它们**标记为失败**。 此外，**PodGC** 在清理孤儿 Pod 时会**添加 Pod 干扰状况**。请**参阅 Pod 干扰状况** 以了解更多详情。
