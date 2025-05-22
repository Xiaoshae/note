# Systemd

Systemd 单位文件使用 INI 格式，分为多个节（如 [Unit]、[Service]、[Install]），每个节包含键值对，定义单位的行为。文件通常位于 /lib/systemd/system（系统默认）或 /etc/systemd/system（用户自定义，优先级更高）。服务单位文件以 .service 结尾，文件名通常与服务名一致（如 nginx.service）。



## Unit

[Unit] 节描述单位的基本信息和依赖关系，适用于所有单位类型。



### Description

`Description=` 是一个简短的、人类可读的标题，用于描述某个单元（unit）。这个标题可能会被 `systemd` 或其他用户界面（UI）用作用户可见的标签，用于标识该单元。

这个字符串应该能够**明确标识该单元**，而**不是仅仅描述它**的功能。尽管字段名字是“Description”，但它**更像是单元的“标题”或“名称”**。



这个字符串不应该只是简单地重复单元的名称（比如单元文件名）。

**好的示例**：**“Apache2 Web Server”**（明确指出了这是 **Apache2** 的 Web 服务器，信息清晰）。

**不好的示例**：

- **“high-performance lightweight HTTP server”**（描述过于宽泛，缺乏具体指向）；
- **“Apache2”**（对不熟悉 **Apache** 的人缺乏意义，且仅仅是单元名的重复）。



由于 **systemd** 会将这个字符串用作状态消息中的名词（例如 **“Starting description...”**、**“Started description.”** 等），因此：它应当首字母大写，且不应该是一个完整的句子，也不应包含连续的动词短语。

**不好的示例**：

- **“exiting the container”**（包含连续动词，像是描述一个动作）；
- **“updating the database once per day”**（像是一个完整的句子或描述性短语）。



### Documentation

`Documentation=` 这是一个以空格分隔的URI列表，引用了该单位或其配置的文档。

仅接受以下类型的 **URI："http://"、"https://"、"file:"、"info:"、"man:"**。

建议首先引用解释该单位用途的文档，然后是关于如何配置的文档，最后是其他相关文档。



### After Before

`After=` 和 `Before=` 是 systemd 单位配置文件中的两个选项，用于指定单位之间的启动和关闭顺序。



这两个选项接受一个**以空格分隔的单位名称列表**，并且 `After=` 和 `Before=`  可以多次定义。如果多次定义，将会对列表中的所有单位名称建立依赖关系。

```
[Unit]
After=s1.service s2.service
After=s3.service
After=s4.service s5.serivce
```

最终，所有 **After** 内容将被整合为一个整体。

```
After=s1.service s2.service s3.service s4.service s5.service
```



如果某个 Unit 如（**s2.service**），设置了 `After=s1.service` ，那么当两个单位同时启动时，`s2.service` 必须在 `s1.service` 完全启动之后才开始启动。

如果 **s1.service**，设置了 `Before=s2.service` ，那么当两个单位同时启动时，`s1.service` 必须在 `s2.service` 开始启动之前完成启动。



当两个单位之间存在顺序依赖关系（通过 `After=` 或 `Before=` 定义）并且需要关闭时，关闭顺序与启动顺序相反。

如果单位 s2 配置了 `After=s1`，那么在启动时 s2 在 s1 之后启动；而在关闭时，s2 会在 s1 之前关闭。



如果一个单位需要关闭，而另一个单位需要启动（无论依赖关系是 `After=` 还是 `Before=`），关闭操作总是优先于启动操作。



`After=` 和 `Before=` 是**顺序依赖关系**，它们与**需求依赖关系**（如 `Requires=`、`Wants=`、`Requisite=`、`BindsTo=`）是独立的、互不影响的。



### Wants

`Wants=` 配置对其他 Unit 的**弱依赖关系**，此选项可以多次指定。

```
[Unit]
Wants=s1.service
```



在 **s2.service** 中定义 `Wants=s1.service` 后，启动 s2.service 时，若 s1.service 未处于活动状态，系统会尝试启动它。即使 s1.service 启动失败，也不会影响 **s2.service 的启动**，后者仍将正常运行。



请注意，依赖关系不会影响服务启动或停止的顺序。顺序必须通过 After= 或 Before= 选项独立配置。

如果 s2.service 单元通过 **Wants=** 配置引入了 s1.service 单元，但未使用 **After=** 或 **Before=** 配置启动顺序，那么在 s2.service 被激活时，两个单元将同步启动，不会有任何延迟。



### Requires

`Requires=` 配置对其他 Unit 的**强依赖关系**，此选项可以多次指定。



如果此单元被激活，列出的其他单元也将被激活。如果其中一个其他单元未能激活，并且对失败单元设置了 After= 的顺序依赖，则此单元将不会启动。

如果对 **Requires=** 中列出的单元指定了 **After=**，则此单元会**在这些单元成功启动后才会正式开始启动**。

如果仅使用 `Requires=` ，没有对这些单元指定 `After=`，则**列举的单元会和此单元同时启动**，如果列举的单元启动失败，此单元也会启动失败。



即使没有显式指定 `After=`，如果依赖单元被明确停止（或重启），当前单元也会被停止（或重启）。



**注意1**

`Requires=` 并不强制要求依赖单元在当前单元运行的整个过程中始终保持激活状态。它只在启动时检查依赖单元是否能够成功激活。如果依赖单元在启动后因某些原因停用，当前单元不会因此自动停止。

单元 B 依赖单元 A，两者在启动时均成功运行。若运行过程中单元 A 意外关闭（如被手动 **kill -9** 强制终止），且单元 A 未设置重启策略，则单元 B 不受影响，将继续运行。

然而，若单元 A 设置了重启策略，在被强制终止后，**systemd** 会尝试重启单元 A，这一重启行为将波及单元 B，导致单元 B 也被重启。



**注意2**

如果依赖单元因为条件检查失败（比如某个路径不存在或不符合条件）而无法启动，这种失败不会被视为 `Requires=` 依赖的“失败”。条件检查失败不会影响当前单元的启动。

假设单元 A 的 `Requires=` 依赖于单元 B，而单元 B 设置了一个条件 `ConditionPathExists=/some/path`，如果 `/some/path` 不存在，单元 B 不会启动，但这种失败不会导致单元 A 的启动失败。



**注意3**

若要确保一个单元在没有特定其他单元也处于激活状态时永远不会处于激活状态，请结合 After= 使用 BindsTo= 依赖类。



### Requisite

`Requisite=` 如果依赖的单元没有启动，systemd 不会尝试启动它们，而是直接让当前单元启动失败。



### BindsTo

`BindsTo=` 是一种依赖关系指令，类似于 `Requires=`，但它的约束力更强。

它不仅要求指定的依赖单元（例如某个服务、设备或挂载点）必须存在并被激活，还规定了如果被绑定的单元停止或进入非活动状态（inactive state），当前单元也会被强制停止。

当 `BindsTo=` 和 `After=` 在同一个单元上一起使用时，依赖关系变得更加严格。当前单元只有在被绑定的单元处于活动状态（active state）时才能保持活动状态。

如果被绑定的单元因为某些条件检查未通过（例如 `ConditionPathExists=` 或 `ConditionPathIsSymbolicLink=` 等条件不满足）而被跳过（skipped），当前单元也会被停止（如果它正在运行）。



## Service

[Service] 节定义服务的具体行为，如启动命令、重启策略等。

Service 单元文件可能包含 [Unit] 和 [Install] 部分，这些部分在 systemd.unit(5) 中有详细描述。

Service 单元文件必须包含一个 [Service] 部分，该部分包含有关服务及其所监督进程的信息。



### Type

`Type=` 定义了 systemd 如何**判断一个服务启动完成**，并决定是否可以启动后续依赖的服务单位。



systemd 支持以下几种类型：`simple`、`exec`、`forking`、`oneshot`、`dbus`、`notify`、`notify-reload` 和 `idle`。每种类型对应不同的启动完成判断机制。这里只介绍 `simple`、`exec` 和 `forking`。



**启动顺序**

在讲解这三种类型前，先讲解 systemd 启动 `ExecStart=` 指定的二进制程序的详细流程。

1. 读取服务配置文件

`systemd` 读取服务的 `.service` 文件，解析其中的配置项，例如 `ExecStart=`、`Type=`、`User=`、`Group=` 等。



2. 创建服务进程（fork）：

`systemd` 调用 `fork()` 系统调用，创建一个新的子进程，子进程仍然运行 `systemd` 的代码，为后续执行二进制程序做准备。

在子进程中，`systemd` 设置进程的工作目录（`WorkingDirectory=`）、环境变量（`Environment=`）、用户和组（`User=`、`Group=`）、文件描述符、权限、cgroup、namespace 等。



3. 执行二进制程序（execve）

子进程调用 `execve()` 系统调用，将自身替换为 `ExecStart=` 指定的二进制程序。

`execve` 是一个 Linux/UNIX 系统调用，用于在当前进程中加载并执行一个新的可执行文件，替换当前进程的内存映像。



**simple**

**默认类型**：如果指定了 `ExecStart=` 但没有指定 `Type=` 和 `BusName=`，并且没有使用凭据（credentials），则默认使用 `simple`。

服务管理器在主服务进程通过 `fork()` 创建后立即认为服务已启动（即在 `fork()` 之后，但在设置进程属性或调用 `execve()` 执行服务二进制文件之前）。



**exec**

服务管理器在主服务二进制文件通过 `execve()` 执行后才认为服务已启动。



**forking**

在 Type=forking 的模式下，systemd 会启动 ExecStart 指定的程序，并期望 ExecStart 程序在启动后通过 fork() 创建一个子进程，然后主进程退出，子进程继续作为实际的服务进程运行。当主进程退出后，systemd 会认为服务已经启动成功。

`systemd` 需要知道实际运行的服务进程（即子进程）的 PID（进程 ID），以便对其进行管理（如停止、重新加载或监控状态）。在 `forking` 模式下，由于主进程已经退出，`systemd` 无法直接通过跟踪 `ExecStart` 启动的进程来确定服务的主进程 PID。因此，推荐使用 `PIDFile=` 选项来指定一个文件路径，这个文件应该包含服务的主进程（子进程）的 PID。

`PIDFile=` 指定的文件通常由服务程序本身（即 `ExecStart` 指定的程序或其子进程）在启动时创建。如果设置了 `PIDFile=`，`systemd` 会读取该文件中的 PID，并以此作为服务的实际进程 ID 来进行管理。这样可以确保 `systemd` 能够准确地识别和管理服务进程。

如果不设置 `PIDFile=`，`systemd` 将无法可靠地确定服务的实际主进程 PID。在 `Type=forking` 模式下，主进程已经退出，`systemd` 可能会尝试通过其他方式（如进程组或控制组）来猜测服务的 PID，但这种方式并不总是准确的，尤其是在复杂的 `fork` 行为或多进程服务的情况下。



具体可能导致的问题包括：

1. **无法正确停止或重启服务**：`systemd` 可能无法找到正确的进程来发送停止信号（如 `SIGTERM`），导致服务无法正常关闭。
2. **状态监控不准确**：`systemd` 可能无法判断服务是否仍在运行，导致状态显示错误（如显示服务已停止，但实际上仍在运行）。
3. **资源泄漏或冲突**：如果 `systemd` 误认为服务已停止，可能会尝试重新启动服务，导致多个实例运行或资源冲突。



~~forking 类型适用 ExecStart 指定的程序会在启动后 fork 子进程，主进程退出，子进程成为实际的服务进程。这是传统UNIX服务的行为。~~

~~设置 Type=forking，systemd 会启动 ExecStart 进程，当 ExecStart 进程退出时，systemd 将认为 Unit 已启动。如果 ExecStart 指定的二进制程序不会 fork 子进程后退出，那么 systemd 会一直等待到超时，然后认为 Unit 启动失败。~~

~~如果使用此设置，建议同时使用 PIDFile= 选项，以便 systemd 可以可靠地识别服务的主进程。在父进程退出后，管理器将继续启动后续单元。~~





### ExitType

指定 systemd 应在何时认为服务已经完成。可选值为 main 或 cgroup：



**main（默认值）**

systemd 将在**主进程**退出时认为该单元已停止。因此，它不能与 Type=oneshot 一起使用。

根据服务单元的 `Type=` 设置来确定哪个是主进程：

- 对于 `Type=simple`，主进程通常是服务启动时直接运行的那个进程。
- 对于 `Type=forking`，主进程可能是启动后派生出的某个子进程，而原始进程可能会退出。



**cgroup**

只要 cgroup 中至少有一个进程尚未退出，服务将被视为仍在运行。



### RemainAfterExit

接受一个布尔值，用于指定即使服务的所有进程均已退出，服务是否仍被视为处于活动状态。默认值为 no（否）。



对于某些只需要运行一次就完成任务的服务（例如系统初始化脚本或某些清理任务），可以设置 `RemainAfterExit=yes`，以便在任务完成后，systemd 仍然认为服务是“成功的”或“活动的”，而不会误判为失败。



管理员可以通过 `systemctl stop <服务名>` 命令手动停止服务。无论 `RemainAfterExit` 设置为 `yes` 还是 `no`，此操作都会将服务状态更新为“stopped”（已停止），从而结束服务的活动状态。



### GuessMainPID

接受一个布尔值，用于指定当无法可靠确定服务的主进程ID（PID）时，systemd 是否应尝试猜测主进程ID。

除非设置了 Type=forking 且未设置 PIDFile=，否则此选项将被忽略，因为对于其他类型或明确配置了 PID 文件的情况，主进程 ID 总是已知的。

如果守护进程包含多个进程（**ExecStart 进程 fork 多个子进程**等），猜测算法可能会得出错误的结论。如果无法确定主进程 ID，服务的故障检测和自动重启功能将无法可靠运行。

默认值为 yes（是）。



### PIDFile

指定服务进程的PID文件路径。建议在服务的 Type= 设置为 forking 时使用此选项。

指定的 PID 文件路径通常位于 `/run/` 目录下。如果配置的是相对路径，`systemd` 会自动在前面加上 `/run/` 前缀。例如，`PIDFile=myservice.pid` 会被解析为 `/run/myservice.pid`。



服务启动后，`systemd` 会从这个 PID 文件中读取服务的**主进程 ID**，但不会写入这个 PID 文件。当服务停止后，如果 PID 文件仍然存在，`systemd` 会将其删除。



PID文件（存储进程ID的文件）的所有权不需要一定是特权用户。然而，如果这个文件的拥有者是一个非特权用户，那么为了确保安全，会对这个文件施加一些额外的限制条件：

- **文件不能是符号链接（symlink）**：PID文件不能是一个指向其他文件的符号链接，尤其是不能指向由其他用户（不同于文件拥有者）所拥有的文件。
- **PID文件必须指向属于该服务的进程**：PID文件中记录的进程ID必须对应一个已经属于该服务的进程。



systemd 在管理服务时，会为每个服务分配一个 控制组（cgroup）。cgroup 是一种 Linux 内核机制，用于分组和限制进程的资源使用。systemd 会将服务启动的所有进程（包括主进程和可能的子进程）放入该服务的专属 cgroup 中。这样，systemd 可以通过检查进程是否属于服务的 cgroup 来确定进程是否“属于”该服务。



# Install

`[Install]` 部分包含了单元文件的安装信息，主要用于指定单元在被启用（`systemctl enable`）或禁用（`systemctl disable`）时的行为。这个部分不会影响单元的运行时行为，仅在安装或卸载单元时起作用。



