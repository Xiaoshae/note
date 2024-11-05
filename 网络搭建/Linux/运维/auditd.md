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
auditctl -a always,exit -S all -F exe=/usr/bin/ls -k ls-calls
```

- `-a always,exit`：将规则附加到 `exit` 列表，并始终记录。
- `-S all`：指定监视所有系统调用。
- `-F exe=/usr/bin/ls`：指定要监视的可执行文件路径。
- `-k ls-calls`：为规则设置一个键。



### 其他选项

- `-a [list,action | action,list]` 将规则附加到列表末尾并指定动作。注意两个值之间用逗号分隔。省略逗号会导致错误。以下为有效的列表名称：
  - `task` 添加到任务列表。此规则列表仅在创建任务时使用，即当父任务调用 `fork()` 或 `clone()` 时。
  - `exit` 添加到系统调用退出列表。此列表用于在系统调用退出时确定是否应创建审计事件。

- `-w path` 对路径设置监视。如果路径是文件，几乎等同于在系统调用规则中使用 `-F path` 选项。如果监视的是目录，几乎等同于在系统调用规则中使用 `-F dir` 选项。`-w` 形式的写监视是为了向后兼容而存在的，并因性能不佳而被废弃。应将其转换为基于系统调用的形式。使用监视时唯一有效的选项是 `-p` 和 `-k`。
- `-W path` 移除对路径上文件系统对象的监视。规则必须完全匹配。

- `-l` 列出所有规则，每行一条。

- `-v` 打印 `auditctl` 的版本。