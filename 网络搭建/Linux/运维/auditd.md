# auditd 服务

auditd 是 Linux 下的审计守护程序。



## auditctl 

通过 `auditctl`设置文件、目录和系统调用的监控规则。



### 监控文件和目录

示例 1：监控文件

```
auditctl -w /path/to/file -p [r|w|x|a] -k key_name
```

- `-w /path/to/file`：指定要监视的文件路径。
- `-p [r|w|x|a]`：指定要监视的权限类型：
  - `r`：读取
  - `w`：写入
  - `x`：执行
  - `a`：属性更改
- `-k key_name`：为规则设置一个键，方便后续查询和管理。



示例 2：递归监控目录

```
auditctl -w /path/to/directory -p [r|w|x|a] -k key_name
```



示例 3：监控特定用户的文件访问

```
auditctl -a always,exit -S openat -F auid=510 -k user510-files
```

- `-a always,exit`：将规则附加到 `exit` 列表，并始终记录。
- `-S openat`：指定要监视的系统调用。
- `-F auid=510`：指定要监视的用户 ID。
- `-k user510-files`：为规则设置一个键。



示例3：监控管理员访问其他用户的文件

```
auditctl -a always,exit -F dir=/home/ -F uid=0 -C auid!=obj_uid -k admin-access
```

- `-a always,exit`：将规则附加到 `exit` 列表，并始终记录。
- `-F dir=/home/`：指定要监视的目录。
- `-F uid=0`：指定要监视的用户 ID 为 0（root 用户）。
- `-C auid!=obj_uid`：条件表达式，表示 `auid`（审计用户 ID）不等于 `obj_uid`（目标文件的用户 ID）。
- `-k admin-access`：为规则设置一个键。



### 监控系统调用

监控特定系统调用

```
auditctl -a [list,action | action,list] -F arch=[b32|b64] -S syscall -F [field=value] -k key_name
```

- `-a [list,action | action,list]`：将规则附加到指定列表并指定动作。常见的列表有：

  - `task`：任务列表，用于创建任务时的审计。
  - `entry`：入口列表，用于系统调用进入时的审计。
  - `exit`：出口列表，用于系统调用退出时的审计。

- `-F arch=[b32|b64]`：指定架构，`b32` 表示 32 位，`b64` 表示 64 位。

- `-S syscall`：指定要监视的系统调用名称或编号。

- ```
  -F [field=value]
  ```

  ：指定过滤条件，常见的字段有：

  - `a0, a1, a2, a3`：系统调用的前四个参数。
  - `arch`：系统调用的架构。
  - `auid`：审计用户 ID。
  - `egid`：有效组 ID。
  - `euid`：有效用户 ID。
  - `exe`：执行的程序路径。
  - `exit`：系统调用的返回值。
  - `fsgid`：文件系统组 ID。
  - `fsuid`：文件系统用户 ID。
  - `gid`：组 ID。
  - `inode`：inode 编号。
  - `path`：文件路径。
  - `perm`：文件操作权限。
  - `pid`：进程 ID。
  - `ppid`：父进程 ID。
  - `success`：成功或失败（0 表示失败，1 表示成功）。
  - `uid`：用户 ID。

- `-k key_name`：为规则设置一个键。





示例 1：监控 openat 系统调用

```
auditctl -a always,exit -F arch=b64 -S openat -F dir=/etc -F success=0 -F auid=1000 -k failed-open
```

- `-a always,exit`：将规则附加到 `exit` 列表，并始终记录。
  - `always`：表示无论系统调用成功与否，都要记录。
  - `exit`：表示在系统调用退出时进行审计。
- `-F arch=b64`：指定架构为 64 位。
- `-S openat`：指定要监视的系统调用名称。
- `-F dir=/etc`：指定要监视的目录路径。
- `-F success=0`：只记录失败的系统调用。
- `-F auid=1000`：指定要监视的审计用户 ID（通常对应于登录用户）。
- `-k failed-open`：为规则设置一个键，方便后续查询和管理。



示例 2：同时指定多个系统调用，多个UID

```
auditctl -a always,exit -F arch=b64 -S openat,close -F dir=/etc -F success=0 -F auid=1000,2000 -k failed-open-close
```

- `-a always,exit`：将规则附加到 `exit` 列表，并始终记录。
- `-F arch=b64`：指定架构为 64 位。
- `-S openat,close`：同时指定要监视的多个系统调用，用逗号分隔。
- `-F dir=/etc`：指定要监视的目录路径。
- `-F success=0`：只记录失败的系统调用。
- `-F auid=1000`：指定要监视的审计用户 ID。
- `-k failed-open-close`：为规则设置一个键，方便后续查询和管理。



示例 3：监控特定程序的所有系统调用

```
auditctl -a always,exit -S all -F arch=b64 -k all-syscalls
auditctl -a always,exit -S all -F arch=b32 -k all-syscalls
```

- `-a always,exit`：将规则附加到 `exit` 列表，并始终记录。
- `-S all`：指定监视所有系统调用。
- `-F arch=b64`：指定要监视的可执行文件类型。
- `-k all-calls`：为规则设置一个键。



```
auditctl -a always,exit -F arch=b64 -S openat,excve -k all-syscalls
auditctl -a always,exit -F arch=b32 -S openat,excve -k all-syscalls
```



### 其他选项

- `-a [list,action | action,list]` 将规则附加到列表末尾并指定动作。注意两个值之间用逗号分隔。省略逗号会导致错误。以下为有效的列表名称：
  - `task` 添加到任务列表。此规则列表仅在创建任务时使用，即当父任务调用 `fork()` 或 `clone()` 时。
  - `exit` 添加到系统调用退出列表。此列表用于在系统调用退出时确定是否应创建审计事件。

- `-w path` 对路径设置监视。如果路径是文件，几乎等同于在系统调用规则中使用 `-F path` 选项。如果监视的是目录，几乎等同于在系统调用规则中使用 `-F dir` 选项。`-w` 形式的写监视是为了向后兼容而存在的，并因性能不佳而被废弃。应将其转换为基于系统调用的形式。使用监视时唯一有效的选项是 `-p` 和 `-k`。
- `-W path` 移除对路径上文件系统对象的监视。规则必须完全匹配。

- `-l` 列出所有规则，每行一条。

- `-v` 打印 `auditctl` 的版本。



## ausearch

`ausearch` 是一个非常强大的工具，用于根据不同的标准查询审计守护进程的日志。

```
ausearch -i
```



### 基本搜索参数

- `-a, --event audit-event-id`：根据给定的事件ID搜索事件。
- `-c, --comm command-name`：根据命令名搜索事件。
- `-f, --file file-name`：根据文件名搜索事件，匹配普通文件以及 AF_UNIX 套接字。
- `-h, --host host-name`：根据主机名搜索事件，主机名可以是主机名、完全限定域名或数值网络地址。
- `-i, --interpret`：将数值实体解释为文本，例如 uid 被转换为账户名。
- `-k, --key key-string`：根据给定的关键字符串搜索事件。
- `-m, --type event-type`：根据事件类型搜索事件。
- `-n, --node node-name`：根据节点名搜索事件。
- `-p, --pid process-id`：根据进程ID搜索事件。
- `-pp, --ppid parent-process-id`：根据父进程ID搜索事件。
- `-sc, --syscall syscall-name-or-value`：根据系统调用名或值搜索事件。
- `-se, --context SE-Linux-context-string`：根据 SE-Linux 上下文字符串搜索事件。
- `-su, --subject SE-Linux-context-string`：根据 SE-Linux 主体上下文字符串搜索事件。
- `-o, --object SE-Linux-context-string`：根据 SE-Linux 对象上下文字符串搜索事件。
- `-t, --time time-stamp`：根据时间戳搜索事件。
- `-te, --end [end-date][end-time]`：搜索时间戳等于或早于给定结束时间的事件。
- `-ts, --start [start-date][start-time]`：搜索时间戳等于或晚于给定开始时间的事件。
- `-u, --user user-id`：根据用户ID搜索事件。
- `-ua, --uid-all all-user-id`：搜索具有给定用户ID、有效用户ID或登录用户ID的事件。
- `-ue, --uid-effective effective-user-id`：搜索具有给定有效用户ID的事件。
- `-ui, --uid user-id`：搜索具有给定用户ID的事件。
- `-ul, --loginuid login-id`：搜索具有给定登录用户ID的事件。
- `-uu, --uuid guest-uuid`：搜索具有给定虚拟机UUID的事件。
- `-vm, --vm-name guest-name`：搜索具有给定虚拟机名称的事件。
- `-w, --word`：字符串匹配必须匹配整个单词，适用于文件名、主机名、终端、键和 SE Linux 上下文。
- `-x, --executable executable`：根据给定的可执行文件名搜索事件。

### 输出格式参数

- ``--format option`：匹配搜索条件的事件使用此选项进行格式化。支持的格式有：raw、default、interpret、csv和text。
  - `raw`：输出完全未格式化的记录。
  - `default`：默认格式，包括一行作为视觉分隔符，指示时间戳，然后是事件的记录。
  - `interpret`：将数值实体解释为文本。
  - `csv`：以逗号分隔值（CSV）格式输出结果，适合导入分析程序。
  - `text`：将事件转换为英文句子，更容易理解，但会损失细节。
- `--extra-labels`：当格式模式为csv时，如果存在主体和对象标签，则会增加信息列。
- `--extra-obj2`：当格式模式为csv时，如果存在第二个对象，则会增加信息列。
- `--extra-time`：当格式模式为csv时，增加关于分解时间的信息列，以便于子集化。

### 其他参数

- `-g, --group group-id`：根据组ID搜索事件。
- `-ga, --gid-all all-group-id`：搜索具有给定组ID或有效组ID的事件。
- `-ge, --gid-effective effective-group-id`：搜索具有给定有效组ID的事件。
- `-gi, --gid group-id`：搜索具有给定组ID的事件。
- `-h, --help`：显示帮助信息。
- `-if, --input file-name|directory`：使用给定的文件或目录代替日志。
- `-l, --line-buffered`：输出立即刷新到终端，而不是等到缓冲区满或程序结束。
- `-r, --raw`：输出完全未格式化的记录。
- `-sv, --success success-value`：根据给定的成功值搜索事件，合法值为 `yes` 和 `no`。
- `-tm, --terminal terminal`：根据给定的终端值搜索事件。
- `-v, --version`：显示版本信息并退出。
- `--checkpoint checkpoint-file`：使用检查点文件中的时间戳恢复搜索。
- `--input-logs`：使用 `auditd.conf` 中的日志文件位置作为搜索的输入。
- `--just-one`：在发出第一个符合搜索条件的事件后停止。
- `--session Login-Session-ID`：搜索与给定登录会话ID匹配的事件。



