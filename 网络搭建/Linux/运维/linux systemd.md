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



### ExecStart

`ExecStart=` 用于定义当服务启动时需要执行的命令，指定了服务启动时运行的具体程序或脚本。



**默认情况下（非 oneshot 类型）**：必须且只能指定一个命令。如果服务类型（`Type=`）不是 `oneshot`，那么 `ExecStart=` 只能出现一次，且必须有一个有效的命令。

**当 `Type=oneshot` 时**：可以多次使用 `ExecStart=` 来定义多个命令，这些命令会在服务启动时按顺序执行。`Type=oneshot` 通常用于只需要执行一次的任务（例如初始化脚本），而不是长期运行的守护进程。



如果没有指定 `ExecStart=` 则服务必须满足以下条件才能被认为是有效的：

- `RemainAfterExit=yes`：表示即使启动命令退出，服务仍然被视为运行状态。
- 至少有一个 `ExecStop=` 命令：用于定义服务停止时执行的命令。



如果配置了多个命令（仅在 `Type=oneshot` 时可能），这些命令会按照它们在单元文件中出现的顺序依次执行。

如果其中一个命令执行失败（返回非零退出码），并且该命令没有以 `-` 开头，那么后续的命令将不会被执行，整个服务单元会被视为启动失败。

**特殊标记 `-`**：如果命令以 `-` 开头（例如 `-/path/to/command`），则即使该命令失败，systemd 也不会将整个单元标记为失败，后续命令仍会继续执行。



除非服务类型设置为 `Type=forking`（表示服务会通过 fork 方式启动子进程），否则通过 `ExecStart=` 启动的进程将被视为服务的**主进程**（main process）。systemd 会跟踪这个主进程的状态来判断服务的运行状态。

如果是 `Type=forking`，systemd 会假定启动命令会 fork 出子进程并退出，systemd 会尝试跟踪 fork 出的子进程作为主进程。



### ExecStartPre ExecStartPost

`ExecStartPre=`：定义在主命令 `ExecStart=` 之前执行的附加命令。这些命令通常用于准备环境，比如创建目录、设置权限等。

`ExecStartPost=`：定义在主命令 `ExecStart=` 成功执行之后执行的附加命令。这些命令通常用于清理、通知或其他后续操作。



**语法**：可以指定多个命令行（一行一个命令），并且命令会按顺序串行执行（一个接一个）。

```
[Service]
ExecStartPre=/bin/echo "Starting preparation step 1"
ExecStartPre=/bin/mkdir -p /var/run/myapp
ExecStart=/usr/bin/myapp --config /etc/myapp.conf
ExecStartPost=/bin/echo "Service started, running post-step 1"
ExecStartPost=-/bin/touch /tmp/myapp.started
```



如果 `ExecStartPre=` 或 `ExecStartPost=` 中定义的命令（没有以 `-` 开头的命令）执行失败，则后续命令不会被执行，并且整个服务单元会被认为失败（`failed`）。



`ExecStartPre=` 的执行时机：只有当所有没有以 `-` 开头的 `ExecStartPre=` 命令都成功退出后，`ExecStart=` 定义的主命令才会开始执行。

`ExecStartPost=` 的执行时机：只有当 `ExecStart=` 定义的主命令根据服务类型（`Type=`）成功执行后，`ExecStartPost=` 命令才会开始执行。成功的定义取决于服务类型：

- `Type=simple` 或 `Type=idle`：主进程已经启动。
- `Type=oneshot`：最后一个 `ExecStart=` 进程成功退出。
- `Type=forking`：初始进程成功退出（通常是父进程退出，子进程继续运行）。



`ExecStartPre=` 不适合启动长期运行的进程：当 `ExecStartPre=` 中定义的所有命令执行完毕后，systemd 会确保在启动 `ExecStart=` 之前，将通过 `ExecStartPre=` 启动的任何进程（包括这些进程创建的子进程）全部终止。

如果 `ExecStartPre=`、`ExecStart=` 或 `ExecStartPost=` 中的命令失败（且没有以 `-` 开头）或超时，且服务尚未完全启动（fully up），systemd 会继续执行 `ExecStopPost=` 中定义的命令，但会跳过 `ExecStop=` 中的命令。

`ExecStartPost=` 的执行会被纳入 `Before=` 和 `After=` 依赖顺序的考虑中。如果某个服务单元的启动依赖于另一个服务单元，那么只有在 `ExecStartPost=` 成功执行完毕后，依赖于它的服务才会开始启动。





### ExecCondition

`ExecCondition=`  用于在 `ExecStartPre=` 命令之前执行一些命令。支持多行命令。无论服务类型（Type=）是什么，这些命令都会按顺序依次执行。

`ExecCondition=` 是一个条件检查机制，根据命令的执行结果决定是否继续执行后续的启动流程。

- 如果 `ExecCondition=` 中定义的命令以退出码 1 到 254（包含）退出，那么后续的命令（包括 `ExecStartPre=` 和其他）会被跳过，但服务单元**不会被标记为失败**。
- 如果命令以退出码 255 或以异常方式退出（例如超时、被信号终止等），那么服务单元会被**标记为失败**，并且后续命令也会被跳过。
- 如果命令以退出码 0 或与 `SuccessExitStatus=` 定义的成功退出码匹配，则会继续执行后续命令。



### ExecReload

`ExecReload=` 用于定义当需要重新加载服务配置时执行的命令。它可以接受多条命令行。

当你运行 `systemctl reload 服务名` 时，`ExecReload=` 中定义的命令会被执行，用于触发服务的配置重新加载，而不需要完全重启服务（即不停止服务进程）。



**占位符和环境变量替换**：`ExecReload=` 支持与 `ExecStart=` 相同的占位符（specifier）和环境变量替换规则。比如可以用 `%i` 表示实例名，或者通过环境变量传递参数。

**特殊环境变量 `$MAINPID`**：`systemd` 会为 `ExecReload=` 设置一个特殊的环境变量 `$MAINPID`，它表示服务主进程的 PID（进程 ID）。这在需要向主进程发送信号时非常有用。



**示例 1：使用信号触发重新加载**

```
ExecReload=kill -HUP $MAINPID
```

这条命令使用 `kill` 工具向服务的主进程（通过 `$MAINPID` 获取进程 ID）发送 `HUP` 信号（Hang Up 信号）。

这种方式通常**不是一个好选择**，因为发送信号属于**异步操作**。具体来说，发送信号后，kill 进程会立即结束，但这并不意味着接收信号的进程已经完成了配置重新加载。`systemd` 通过 kill 进程的退出代码来判断配置重新加载是否完成，而在这种情况下，无法确保目标进程真正完成了重新加载。这可能会在需要多个服务按顺序重新加载时引发问题（例如，服务 A 依赖于服务 B 的重新加载完成）。



**示例 2：同步重新加载（推荐方式）**

```
ExecReload=busctl call org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus \
        ReloadConfig
```

这条命令使用 `busctl` 工具通过 D-Bus（一种进程间通信机制）调用 `org.freedesktop.DBus` 服务的 `ReloadConfig` 方法，触发配置重新加载。

与发送信号不同，这种方式是**同步的**，即命令会等待重新加载操作完成后再返回。这确保了 `systemd` 知道重新加载是否成功，避免了异步操作带来的不确定性。



### ExecStop

`ExecStop=` 用于定义在停止服务时需要执行的命令。通常用于优雅地关闭服务，比如通知服务进程进行清理并安全退出。



当你通过 `systemctl stop` 或其他方式请求停止一个服务时，`ExecStop=` 中定义的命令会被执行。



如果没有定义 `ExecStop=`，`systemd` 会直接根据 `KillMode=` 和 `KillSignal=`（或 `RestartKillSignal=`）设置，向服务进程发送终止信号（比如 SIGTERM 或 SIGKILL）来强制停止服务。



`ExecStop=` 中的命令应该是**同步操作**，也就是说，命令需要等待服务进程完全停止后再返回。

如果命令只是简单地发送一个终止信号给服务进程，而不等待其实际停止，可能会导致问题。因为在命令执行结束后，`systemd` 会根据 `KillMode=` 和 `KillSignal=` 立即杀死剩余的进程，这可能导致服务无法干净地停止。



**执行条件**

`ExecStop=` 中的命令**只有在服务成功启动后才会执行**。如果服务从未启动，或者启动失败（例如 `ExecStart=`、`ExecStartPre=` 或 `ExecStartPost=` 中的命令失败或超时），`ExecStop=` 不会被调用。

如果服务启动失败并需要执行一些清理操作，应该使用 `ExecStopPost=` 来定义命令。



**服务的停止行为**

即使服务进程已经自行终止或被杀死，`ExecStop=` 中的停止命令仍然会执行。因此，停止命令需要能够处理这种情况（例如检查进程是否仍然存在）。

如果在执行停止命令时，`systemd` 知道主进程（通过 `$MAINPID` 变量表示）已经退出，那么 `$MAINPID` 变量会是未设置的状态。



**重启操作**

服务重启（通过 `systemctl restart`）实际上是先执行停止操作（调用 `ExecStop=` 和 `ExecStopPost=`），然后再执行启动操作（调用 `ExecStart=` 等）。



**推荐用法**

`ExecStop=` 应该用于与服务进程通信，请求其优雅地终止（例如发送一个停止信号并等待其完成清理）。

如果需要在服务停止后进行一些“事后清理”（post-mortem clean-up），比如删除临时文件等，应该使用 `ExecStopPost=`。





### ExecStopPost

`ExecStopPost=`  用于定义在服务停止后（post-stop）执行的额外命令。`ExecStopPost=` 可以接受多条命令，当一个服务被停止时（无论是正常停止还是异常停止），会执行 `ExecStopPost=` 指定一些额外的清理或后续操作命令。



**ExecStop= 仅在服务正常停止时执行**，`ExecStopPost=` 会在服务停止后执行（任何情况）。



**环境变量**

`ExecStopPost=` 中配置的命令在执行时，会被传入一些特定的环境变量，这些变量包含了服务的运行结果和状态信息：

- `$SERVICE_RESULT`：服务的运行结果（比如成功、失败等）。
- `$EXIT_CODE`：主进程的退出码。
- `$EXIT_STATUS`：主进程的退出状态。



**Before= 和 After=** 

`ExecStopPost=` 的执行会被纳入 `Before=` 和 `After=` 依赖关系的考虑中。

如果服务 A 的配置文件中设置了 `After=服务B`，那么服务 A 必须在服务 B 完全停止后才能开始停止。这里的“完全停止”包括服务 B 执行完 `ExecStop=` 和 `ExecStopPost=` 的所有命令。



**推荐用途**

ExecStopPost= 推荐用于执行清理操作，尤其是在服务启动失败的情况下。比如：

- 删除临时文件。

- 撤销某些初始化操作。
- 记录日志或状态信息。

需要注意的是，配置在 ExecStopPost= 中的命令必须能够处理服务未完全初始化或启动失败的情况。也就是说，这些命令不能依赖于服务已经完全启动或正常运行的前提条件。

另外，由于服务进程可能已经退出，ExecStopPost= 中的命令不应该尝试与服务进程通信。



### Restart

`Restart=` 选项用于控制当服务进程退出、被终止（例如被信号杀死）或遇到超时（包括启动、停止、重载操作超时或看门狗超时）时，是否需要重启服务。这个进程可以是主服务进程，也可以是与 `ExecStartPre=`、`ExecStartPost=`、`ExecStop=`、`ExecStopPost=` 或 `ExecReload=` 相关的辅助进程。

如果进程的退出是由 `systemd` 主动操作引起的（例如通过 `systemctl stop` 或 `systemctl restart` 停止服务），那么即使配置了重启策略，服务也不会被重启。



`Restart=` 可以设置为以下值，每种设置对应不同的重启条件：

- **`no`**（默认值）：服务不会在任何情况下自动重启。
- **`on-success`**：仅当服务进程以“干净”的方式退出时重启。干净退出包括：
  - 退出码为 0；
  - 对于非 `Type=oneshot` 的服务，接收到 `SIGHUP`、`SIGINT`、`SIGTERM` 或 `SIGPIPE` 信号；
  - 退出状态或信号在 `SuccessExitStatus=` 中指定。
- **`on-failure`**：当服务进程以非零退出码退出、被信号终止（包括核心转储，但不包括上述四个“干净”信号）、操作超时（如重载超时）或触发看门狗超时（watchdog timeout）时重启。
- **`on-abnormal`**：当服务进程被信号终止（包括核心转储，但不包括上述四个信号）、操作超时或触发看门狗超时时重启。
- **`on-abort`**：仅当服务进程由于未捕获的信号（且该信号未被定义为干净退出状态）退出时重启。
- **`on-watchdog`**：仅当服务的看门狗超时（watchdog timeout）到期时重启。
- **`always`**：无论服务是以干净方式退出、被信号异常终止还是遇到超时，都会重启服务。



**注意**：对于 `Type=oneshot` 类型的服务，即使设置为 `always` 或 `on-success`，在干净退出时也不会重启。



### RestartSec RestartSteps RestartMaxDelaySec

`RestartSec= ` 配置服务在重启之前需要等待的时间间隔。

**取值**：可以是一个无单位的数值（表示秒数），也可以是一个带有时间单位的值，例如 "5min 20s"（表示 5 分钟 20 秒）。

**默认值**：100 毫秒（100ms）。



`RestartMaxDelaySec=` 配置**重启间隔的最大时间**，**间隔时间即随着重启次数增加**，间隔时间最终不会超过这个值。

- **取值**：与 `RestartSec=` 格式相同，可以是一个时间值，也可以是 "infinity"（表示禁用此限制）。
- **默认值**："infinity"（无限制）。



`RestartSteps=` 配置自动重启时间间隔从 `RestartSec=` 增加到 `RestartMaxDelaySec=` 所需的步数。

- **取值**：一个正整数，或者 0（表示禁用此功能）。
- **默认值**：0（禁用）。



如果仅设置了 `RestartSec=5`，每次自动重启前，`systemd` 都会**等待固定时间，**即 `RestartSec=` 指定的 5 秒。



根据文档，`RestartMaxDelaySec=` 和 `RestartSteps=` 必须同时设置时才有效。

假设某个服务的配置文件中有如下设置：

```
RestartSec=5
RestartSteps=3
RestartMaxDelaySec=30
```

服务初始重启间隔为 5 秒（`RestartSec=5`）。

随着重启次数增加，间隔时间会逐步增加，最多分成 3 步（`RestartSteps=3`），最终达到最大 30 秒（`RestartMaxDelaySec=30`）。

- 假设每次增加的步长是均匀的，那么间隔时间可能是：
  - 第 1 次重启：5 秒
  - 第 2 次重启：约 13 秒（5 + (30-5)/3）
  - 第 3 次重启：约 21 秒
  - 第 4 次及以后：30 秒（达到最大值）



`RestartSec=` 定义的时间仅适用于由 `systemd` 自动触发的重启行为，手动重启是立即触发的。



### TimeoutStartSec

`TimeoutStartSec=` 用于配置服务启动时等待的时间限制（以秒为单位）。这个参数可以接受一个无单位的数值（表示秒数），或一个时间跨度值，如 **"5min 20s"**（表示5分20秒）。若设置为 **"infinity"**，则禁用超时逻辑，systemd将无限期等待服务启动。



如果一个服务在启动过程中，没有在 `TimeoutStartSec=` 指定的时间内完成启动（即没有发出启动完成的信号），那么 `systemd` 会认为该服务启动失败。

启动失败后，`systemd` 会根据 `TimeoutStartFailureMode=` 设置的行为来决定如何处理（例如关闭服务）。



`TimeoutStartSec=` 不仅适用于服务的启动，也适用于服务的重载（reload）操作：

- 无论是通过 `ExecReload=` 指定的重载命令，还是通过 `Type=notify-reload` 实现的动态重载逻辑，`TimeoutStartSec=` 都会生效。
- 如果重载操作在指定的超时时间内未完成，`systemd` 会认为重载失败。此时，它会继续按照之前的配置和状态运行，而不会因为重载失败而停止或崩溃。但会记录错误日志，并且类似 `systemctl reload` 的命令会返回失败状态。



### TimeoutStopSec

它配置等待每个 ExecStop= 命令的时间。如果其中任何一个命令超时，后续的 ExecStop= 命令将被跳过，并且服务将通过 SIGTERM 信号终止。

如果未指定 ExecStop= 命令，服务主进程将立即收到 SIGTERM 信号。



它还配置**发送 SIGTERM 信号后**。如果服务在指定时间（TimeoutStopSec）内未终止，将通过 SIGKILL 信号强制终止。



接受以秒为单位的无单位数值，或如“5min 20s”这样的时间跨度值。传入“infinity”以禁用超时逻辑。



### TimeoutSec

这是一个简写方式，用于将 TimeoutStartSec= 和 TimeoutStopSec= 同时配置为指定值。



### TimeoutStartFailureMode TimeoutStopFailureMode

定义当服务在 **TimeoutStartSec= 时间内未能启动成功，或者在 TimeoutStopSec= 时间内未能停止**时所采取的行动。

可选值包括 terminate、abort 和 kill。两个选项的默认值均为 terminate。

**terminate**（默认值）：

- 如果设置为 terminate，服务将通过发送 KillSignal= 中指定的信号（默认为 SIGTERM，参见 systemd.kill(5)）优雅地终止。
- 发送 `KillSignal=` 后，如果服务未能在 TimeoutStopSec= 时间内终止，则会发送 FinalKillSignal= 信号。如果仍然未停止，最终会



**abort**：

- 如果设置为 `abort`，系统会发送 `WatchdogSignal=` 指定的信号。
- 发送 `WatchdogSignal=` 后，系统会等待 `TimeoutAbortSec=` 指定的时间。
- 如果在 `TimeoutAbortSec=` 时间结束后服务仍未停止，系统会发送 `FinalKillSignal=`，强制终止服务进程。



**kill**：

- 如果设置为 `kill`，系统会立即发送 `FinalKillSignal=`（通常是 `SIGKILL`，强制终止进程），而不等待任何额外的超时。



`TimeoutStartFailureMode=` 和 `TimeoutStopFailureMode=` 与 `Restart=` 在 systemd 的具体行为。

两个 FailureMode 指定启动或停止超时后，如何终止服务。Restart 用于指定**服务停止后的后续行为**，即是否需要重新启动服务以及在什么条件下重启。





### RuntimeMaxSec

配置服务运行的最大时间。如果设置了此项，并且服务运行时间超过了指定的时间，服务将被终止并进入失败状态。

请注意，此设置对 Type=oneshot 类型的服务无效，因为此类服务在激活完成后会立即终止（可使用 TimeoutStartSec= 来限制其激活时间）。

传递 "infinity"（默认值）以配置无运行时间限制。



### SuccessExitStatus

`SuccessExitStatus=` 允许你指定一系列退出状态（exit status），当服务的主进程返回这些状态时，`systemd` 会认为服务是**成功终止**的。

除了默认的成功退出状态 **0** 之外，对于非 **Type=oneshot** 的服务类型，**systemd** 会将主进程因接收到 **SIGHUP**、**SIGINT**、**SIGTERM** 和 **SIGPIPE** 信号而退出视为成功终止的状态。



退出状态可以以以下几种形式指定，多个状态之间用空格分隔：

1. **数值型退出状态**：比如 `75` 或 `250`，直接表示进程退出的状态码。
2. **退出状态名称**：比如 `TEMPFAIL`，这是 `systemd` 定义的一些退出状态的名称。需要注意的是，在 `SuccessExitStatus=` 中使用时，不需要加上前缀 `EXIT_` 或 `EX_`，直接写状态名即可。
3. **终止信号名称**：比如 `SIGKILL` 或 `SIGTERM`，这是操作系统中定义的信号名称，可以通过 `signal(7)` 查看完整的信号列表。



示例：

```
SuccessExitStatus=TEMPFAIL 250 SIGKILL
```

这表示退出状态 `75`（对应名称 `TEMPFAIL`）、`250` 以及终止信号 `SIGKILL` 都被认为是服务的“成功终止”。



## Install

`[Install]` 部分用于承载单元的安装信息。此部分在运行时不会被 systemd(1) 解析；它由 systemctl(1) 工具在单元安装过程中使用的 enable 和 disable 命令所利用。



### Alias

`Alias=`  一个以空格分隔的附加名称列表，表示此单元在安装时应使用的别名。此处列出的名称必须与单元文件名具有相同的后缀（即类型）。

此选项可以多次指定，此时所有列出的名称都会被使用。

在使用 `systemctl enable` 命令安装某个单元（unit）时，系统会根据 `Alias=` 选项中定义的附加名称（别名），为这些别名创建指向原始单元文件名的符号链接（symbolic links）。

注意，并非所有单元类型都支持别名设置，某些类型不支持此设置。具体来说，mount、slice、swap 和 automount 单元不支持别名功能。



### WantedBy RequiredBy UpheldBy

此选项可以多次使用，也可以提供一个以空格分隔的单元名称列表。当通过 systemctl enable 安装此单元时，会在列出的每个单元的 .wants/、.requires/ 或 .upholds/ 目录中创建符号链接。

这相当于在列出的单元与当前单元之间添加了类型为 Wants=、Requires= 或 Upholds= 的依赖关系。有关上述依赖类型的详细说明，请参见 [Unit] 部分的描述。



当使用 systemctl enable myservice.service 时。

例如，如果 myservice.service 的 [Install] 部分包含 WantedBy=multi-user.target，则会创建符号链接 /etc/systemd/system/multi-user.target.wants/myservice.service，指向实际的单位文件（通常在 /etc/systemd/system/ 或 /usr/lib/systemd/system/）。这样，当 multi-user.target 启动时，systemd 会自动加载并启动 myservice.service。



### Also

当此单元被安装或卸载时，需要同时安装或卸载的附加单元。如果用户请求安装或卸载配置了此选项的单元，systemctl enable 和 systemctl disable 也会自动安装或卸载此选项中列出的单元。

此选项可以多次使用，也可以提供一个以空格分隔的单元名称列表。



你可以在 `webserver.service` 的 `[Install]` 部分中添加如下配置：

```
[Install]
WantedBy=multi-user.target
Also=logcollector.service
```

当执行 **systemctl enable webserver.service** 命令时，也相当于执行了 **systemctl enable logcollector.service** 命令。



### DefaultInstance

在模板单元文件中，此选项指定如果模板在未显式设置实例的情况下被启用，则应启用哪个实例。此选项在非模板单元文件中无效。指定的字符串必须可用作实例标识符。









## 生命周期

systemd 单元的生命周期



1. **active（活跃状态）**

单元已经启动（Started）、绑定（Bound）、插入（Plugged in）等，具体含义取决于单元的类型。例如，对于服务单元（Service Unit），可能是进程正在运行；对于设备单元（Device Unit），可能是设备已连接。

表示单元处于正常运行状态。



2. **inactive（非活跃状态）**

单元已停止（Stopped）、未绑定（Unbound）、未插入（Unplugged）等，具体含义也取决于单元类型。

表示单元当前未运行或未处于工作状态。



3. **failed（失败状态）**


类似于 `inactive`，但单元**以失败的方式停止**。失败原因可能包括进程退出时返回错误码、崩溃、操作超时，或者因为重启次数过多而被系统放弃。

表示单元尝试运行但未能成功，需要检查日志或配置来排查问题。



4. **activating（激活中状态）**


单元正在从 `inactive` 状态转变为 `active` 状态。

表示单元正在启动过程中，尚未完全进入运行状态。



5. **deactivating（停用中状态）**


单元正在从 `active` 状态转变为 `inactive` 状态。

表示单元正在停止过程中，尚未完全停止。



6. **maintenance（维护状态）**

单元处于 `inactive` 状态，并且正在进行维护操作。

表示单元暂时不可用，因为系统或管理员正在对其进行维护。



7. **reloading（重新加载状态）**

单元处于 `active` 状态，但正在重新加载其配置。

表示单元正在运行，同时更新配置信息（例如服务重载配置而不停止运行）。



8. **refreshing（刷新状态）**


单元处于 `active` 状态，并且在其命名空间中正在激活一个新的挂载点（Mount）。

表示单元正在运行，同时有新的挂载操作正在进行。



**状态转变**

当一个服务单元被创建（如 s1.service），或被停止，则它处于 **inactive（非活跃状态）**。



当一个 **inactive（非活跃状态）**单元被启动，则它会转变为 **activating（激活中状态）** 状态，会依次执行 **ExecCondition、ExecStartPre 和 ExecStart** 等。

**systemd** 会更具 **ExecCondition** 和 **ExecStartPre** 命令的执行结果来判断服务是否为**失败**，具体判断方法请参考其他。

如果失败，则转为 **failed（失败状态）**。






如果这两个部分为成功，则会开始启动 **ExecStart** 指定的主进程。systemd 根据 `Type=` 的定义**判断一个服务是否启动完成**，如果启动成功，则转变为 **active 状态**。

如果一个服务在启动过程中，没有在 `TimeoutStartSec=` 指定的时间内完成启动（即没有发出启动完成的信号），那么 `systemd` 会认为**该服务启动失败**，单元状态转为 **failed（失败状态）**。



当一个正在运行的服务（处于 **active 状态**），由管理员手动停止（或其他方式触发的停止），则转变为 **deactivating（停用中状态）**，

`ExecStop=` 中定义的命令会被执行。如果没有定义 `ExecStop=`，`systemd` 会直接根据 `KillMode=` 和 `KillSignal=`（或 `RestartKillSignal=`）设置，向服务进程发送终止信号（比如 SIGTERM 或 SIGKILL）来强制停止服务。

`ExecStopPost=`  用于定义在服务停止后（post-stop）执行的额外命令。`ExecStopPost=` 可以接受多条命令，当一个服务被停止时（无论是正常停止还是异常停止），会执行 `ExecStopPost=` 指定一些额外的清理或后续操作命令。

