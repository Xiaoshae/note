# Linux 应急响应

参考资料：

1. [【 中文 | proc - 进程信息伪文件系统 】]([proc(5) — manpages-zh — Debian unstable — Debian Manpages](https://manpages.debian.org/unstable/manpages-zh/proc.5.zh_CN.html))

2. [【 英文 | Linux 进程管理命令速查表 | Linux Process Management Command Cheat Sheet 】]([Linux 进程管理命令速查表 - GeeksforGeeks --- Linux Process Management Command Cheat Sheet - GeeksforGeeks](https://www.geeksforgeeks.org/linux-process-management-command-cheat-sheet/))

3. [【 英文 | Linux 中的进程相关命令 | Process-related Commands in Linux 】]([Linux 中的进程相关命令 --- Process-related Commands in Linux](https://bcalabs.org/subject/process-related-commands-in-linux))





## 进程启动





## 进程信息

/proc 是一个伪文件系统（也称为虚拟文件系统），它提供了关于内核和进程的实时信息。/proc 文件系统并不是存储在磁盘上的，而是由内核动态生成的，当程序或用户访问 /proc 中的文件时，内核会即时创建这些文件的内容。因此，/proc 文件系统的性能开销非常小，因为它不需要读取磁盘。

/proc 里的大多数文件都是只读的, 但也可 以通过写一些文件来改变内核变量。



下面对整个 /proc 目录作一个大略的介绍.

在 /proc 目录里，每个正在运行的进程都有**一个以该进程 ID 命名的子目录**, 其下包括如下的目录和伪文件。

例如 **/proc/1** 对应于PID为 **1** 的进程。

#### cmdline

**cmdline** 该文件保存了**进程的完整命令行**，如果该进程已经**被交换出内存**，或者该**进程已经僵死**，那么就没有任何东西在该文件里，这时候对该文件的读操作将**返回零个字符**，该文件**以空字符 null** 而不是换行符**作为结束标志**。



**交换出内存**

内核会选择一些**不活跃的页面（通常是进程的工作集的一部分）**，并将它们**从物理内存移动到磁盘上的交换分区或交换文件**中。这个过程称为分页（Paging Out）或**交换出（Swapping Out）**。

当一个进程的大部分页面被交换出内存时，它的**命令行信息（存储在 cmdline 文件中）也可能被交换出去**。

在这种情况下，如果你尝试读取 `/proc/<pid>/cmdline` 文件，可能会发现它为空，因为相关的内存页面不在物理内存中。



**进程已经僵死**

**僵死进程**（Zombie Process）是指一个**已经完成执行**但其父进程尚未通过 wait() 或 waitpid() 系统调用来获取其退出状态的进程。**僵死进程仍然保留在进程表中，直到父进程读取其退出状态为止**。

对于僵死进程，`/proc/<pid>/cmdline` 文件通常也是空的，因为进程的用户态数据（包括命令行信息）已经被释放。内核只保留了最小的必要信息（如PID、退出状态）以供父进程查询。



查看进程 ID 为 1 的 cmdline 文件（ **/proc/1/cmdline** ）

```
cat /proc/1/cmdline
/sbin/init
```



#### cwd

**cwd** 一个符号连接, 指向进程当前的工作目录. 

查看进程 ID 为 1 的工作目录（ **/proc/1/cwd** ）

```
ls -l /proc/1/cwd
lrwxrwxrwx 1 root root 0 Dec 22 13:15 /proc/1/cwd -> /

cd /proc/1/cwd; /bin/pwd
/
```



environ 该文件保存进程的环境变量，各项之间以空字符分隔，结尾也可能是一个空字符。因此，如果要输出进程 1 的环境变量，你应该：

```
cat /proc/1/environ | tr '\0' '\n'

HOME=/
init=/sbin/init
NETWORK_SKIP_ENSLAVED=
TERM=linux
BOOT_IMAGE=/vmlinuz-6.8.0-51-generic
drop_caps=
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/
rootmnt=/root
```



#### exe

exe 也是一个符号连接, 指向被执行的二进制代码。

在 Linux 2.0 或者更早的版本下, 对 exe 特殊文件的 readlink(2) 返回一个如下格式的字符串:

[设备号]:节点号

举个例子, [0301]:1502 就是某设备的 1502 节点，该设备的主设备号为 03 (如 IDE，MFM 等驱动器)，从设备号为 01 (第一个驱动器的第一分区)。

而在 Linux 2.2 下，readlink(2) 则给出命令的实际路径名。

另外，该符号连接也可以正常析引用(试图打开 exe 文件实际上将打开一个可执行文件)。

你甚至可以键入 /proc/[number]/exe 来运行 [number] 进程的副本。

带 -inum 选项的 find(1) 命令可以定位该文件。



```
ls -l exe

lrwxrwxrwx 1 root root 0 Dec 22 13:14 exe -> /usr/lib/systemd/systemd
```



#### fd

fd 进程所打开的每个文件都有一个符号连接在该子目录里，以文件描述符命名，这个名字实际上是指向真正的文件的符号连接，（和 exe 记录一样）。

例如, 0 是标准输入, 1 是标准输出，2 是标准错误，等等。

程序有时可能想要读取一个文件却不想要标准输入， 或者想写到一个文件却不想将输出送到标准输出去， 那么就可以很有效地用如下的办法骗过(假定 -i 是输入 文件的标志, 而 -o 是输出文件的标志):

```
foobar -i /proc/self/fd/0 -o /proc/self/fd/1 ...
```

这样就是一个能运转的过滤器。请注意该方法不能用来在文件里搜索，这是因为 fd 目录里的文件是不可搜索的.
在 UNIX 类的系统下, /proc/self/fd/N 基本上就与 /dev/fd/N 相同。实际上，大多数的 Linux MAKEDEV 脚本都将 /dev/fd 符号连接到 [..]/proc/self/fd 上。



#### stat
stat 进程状态信息, 被命令 ps(1) 使用。

现将该文件里各域，以及他们的 scanf(3) 格式说明符，按顺序分述如下：

- **pid** `%d`
    - 进程标识。
- **comm** `%s`
    - 可执行文件的文件名（包括路径）。该文件是否可见取决于该文件是否已被交换出内存。注意：`comm` 字段实际上被括号包围，如 `(name)`。
- **state** `%c`
    - 进程状态，可以是 "R"（正在运行）、"S"（在可中断的就绪态中睡眠）、"D"（在不可中断的等待或交换态中睡眠）、"Z"（僵死）、"T"（被跟踪或被停止）中的一个。
- **ppid** `%d`
    - 父进程 PID。
- **pgrp** `%d`
    - 进程的进程组 ID。
- **session** `%d`
    - 进程的会话 ID。
- **tty** `%d`
    - 进程所使用的终端。如果进程没有关联的控制终端，则此值为 0。
- **tpgid** `%d`
    - 当前拥有该进程所连接终端的进程所在的进程组 ID。如果没有关联的终端，此值为 -1。
- **flags** `%u`
    - 进程标志。每个标志都设了数学位，因此输出里不包括该位。例如，数学仿真位应该是十进制的 4，而跟踪位应该是十进制的 10。
- **minflt** `%u`
    - 进程所导致的小错误（minor faults）数目，这样的小错误不需要从磁盘重新载入一个内存页。
- **cminflt** `%u`
    - 进程及其子进程所导致的小错误（minor faults）数目。
- **majflt** `%u`
    - 进程所导致的大错误（major faults）数目，这样的大错误需要重新载入内存页。
- **cmajflt** `%u`
    - 进程及其子进程所导致的大错误（major faults）数目。
- **utime** `%d`
    - 进程被调度进用户态的时间（以 jiffies 为单位）。
- **stime** `%d`
    - 进程被调度进内核态的时间（以 jiffies 为单位）。
- **cutime** `%d`
    - 进程及其子进程被调度进用户态的时间（以 jiffies 为单位）。
- **cstime** `%d`
    - 进程及其子进程被调度进内核态的时间（以 jiffies 为单位）。
- **priority** `%d`
    - 标准优先级加上 15，在内核里该值总是正的。
- **nice** `%d`
    - 进程的 nice 值。注意：这个字段在某些系统版本中可能不存在。
- **timeout** `%u`
    - 当前至进程的下一次间歇时间，以 jiffies 为单位。
- **itrealvalue** `%u`
    - 由于计时间隔导致的下一个 SIGALRM 发送进程的时延，以 jiffies 为单位。
- **starttime** `%llu`
    - 进程自系统启动以来的开始时间，以 jiffies 为单位。注意：此字段在较新的 Linux 版本中是长整型（`%llu`）。
- **vsize** `%lu`
    - 虚拟内存大小，以字节为单位。
- **rss** `%ld`
    - Resident Set Size（驻留大小）: 进程所占用的真实内存大小，以页为单位。注意：此字段在较新的 Linux 版本中是长整型（`%ld`）。
- **rlim** `%lu`
    - 当前进程的 rss 限制，以字节为单位，通常为 2,147,483,647。
- **startcode** `%lu`
    - 正文部分地址下限。
- **endcode** `%lu`
    - 正文部分地址上限。
- **startstack** `%lu`
    - 堆栈开始地址。
- **kstkesp** `%lu`
    - esp(32 位堆栈指针) 的当前值，与在进程的内核堆栈页得到的一致。
- **kstkeip** `%lu`
    - EIP(32 位指令指针)的当前值。
- **signal** `%u`
    - 待处理信号的 bitmap（通常为 0）。
- **blocked** `%u`
    - 被阻塞信号的 bitmap（对 shell 通常是 0, 2）。
- **sigignore** `%u`
    - 被忽略信号的 bitmap。
- **sigcatch** `%u`
    - 被捕捉信号的 bitmap。
- **wchan** `%lu`
    - 进程在其中等待的通道，实际是一个系统调用的地址。如果有最新版本的 `/etc/psdatabase`，可以在 `ps -l` 的结果中的 WCHAN 域看到文本格式的通道名称。



请注意，不同的 Linux 内核版本和发行版之间，`/proc/[pid]/stat` 文件的格式可能会有轻微差异。此外，某些字段可能在不同版本中存在或不存在，例如 `nice` 字段。对于最新的信息，建议查阅相关系统的文档或源代码。



#### status 

`/proc/[pid]/status` 文件是 Linux 系统中提供有关特定进程详细信息的文本文件。这个文件包含了比 `/proc/[pid]/stat` 更加易读和详细的进程状态信息。

以下是 `/proc/[pid]/status` 文件中常见的字段及其含义：

- **Name:**
    - 进程的名称（通常与可执行文件名相同）。
- **State:**
    - 进程当前的状态，可以是以下之一：
        - R (running)：正在运行或可运行。
        - S (sleeping)：睡眠中（可中断）。
        - D (disk sleep)：不可中断的睡眠（通常等待 I/O 操作完成）。
        - T (stopped)：已停止（通过作业控制信号）。
        - t (tracing stop)：被跟踪器停止。
        - X (dead)：已经死亡（僵尸进程，但尚未被父进程回收）。
        - Z (zombie)：僵尸进程。
        - P (parked)：Linux 3.9+ 中引入的状态，表示进程已被挂起以节省电力。
- **Tgid:**
    - 线程组 ID（Thread Group ID），通常与主进程的 PID 相同，但在多线程程序中，所有线程共享同一个 TGID。
- **Ngid:**
    - Namespace group ID（命名空间组 ID），在使用命名空间时有效。
- **Pid:**
    - 进程 ID（Process ID）。
- **PPid:**
    - 父进程 ID（Parent Process ID）。
- **TracerPid:**
    - 跟踪此进程的调试器或跟踪工具的 PID。如果没有进程在跟踪，则为 0。
- **Uid:**
    - 用户 ID（User ID），包括四个子项：
        - Real：实际用户 ID。
        - Effective：有效用户 ID。
        - Saved Set：保存的设置用户 ID。
        - File：用于文件系统的用户 ID。
- **Gid:**
    - 组 ID（Group ID），类似于 Uid 字段，包含 Real、Effective、Saved Set 和 File 四个子项。
- **FDSize:**
    - 文件描述符表的大小，单位是文件描述符的数量。
- **Groups:**
    - 进程所属的附加组 ID 列表。
- **NStgid, NSpid, NSpgid, NSsid:**
    - 命名空间内的线程组 ID、进程 ID、进程组 ID 和会话 ID。这些字段在使用命名空间时有效。
- **VmPeak:**
    - 虚拟内存使用的峰值（以 kB 为单位）。
- **VmSize:**
    - 当前虚拟内存的大小（以 kB 为单位）。
- **VmLck:**
    - 已锁定到内存中的页面数量（以 kB 为单位）。
- **VmPin:**
    - 已固定的页面数量（以 kB 为单位），从 Linux 4.4 开始可用。
- **VmHWM:**
    - 实际物理内存使用的峰值（以 kB 为单位）。
- **VmRSS:**
    - 实际驻留集大小（Resident Set Size），即实际占用的物理内存大小（以 kB 为单位）。
- **RssAnon:**
    - 匿名页面的 RSS（以 kB 为单位），从 Linux 3.15 开始可用。
- **RssFile:**
    - 文件映射的 RSS（以 kB 为单位），从 Linux 3.15 开始可用。
- **RssShmem:**
    - 共享内存的 RSS（以 kB 为单位），从 Linux 3.15 开始可用。
- **VmData, VmStk, VmExe, VmLib, VmPTE, VmSwap:**
    - 各种类型的内存使用情况，分别对应数据段、栈、代码段、共享库、页表条目和交换空间（以 kB 为单位）。
- **Threads:**
    - 进程中活跃线程的数量。
- **SigQ:**
    - 当前队列中的信号数以及最大队列长度。
- **SigPnd, ShdPnd:**
    - 待处理的信号位图（Signal Pending）和共享待处理的信号位图（Shared Signal Pending）。
- **SigBlk, SigIgn, SigCgt:**
    - 被阻塞、忽略和捕捉的信号位图。
- **CapInh, CapPrm, CapEff, CapBnd, CapAmb:**
    - 进程的能力（capabilities）信息，包括继承的、许可的、有效的、边界和可传递的能力。
- **NoNewPrivs:**
    - 如果设置了 `no_new_privs` 标志，则显示 1；否则显示 0。当设置了这个标志后，进程将无法获得新的特权。
- **Seccomp:**
    - Seccomp 模式，表示进程是否启用了 seccomp 安全模块。
- **Speculation_Store_Bypass:**
    - CPU 规约存储绕过漏洞的状态，可能影响进程的安全性。
- **Cpus_allowed, Cpus_allowed_list:**
    - 进程允许运行的 CPU 集合，以位图形式和列表形式表示。
- **Mems_allowed, Mems_allowed_list:**
    - 进程允许访问的 NUMA 内存节点集合，以位图形式和列表形式表示。
- **voluntary_ctxt_switches:**
    - 自愿上下文切换次数，即进程主动放弃 CPU 的次数。
- **nonvoluntary_ctxt_switches:**
    - 非自愿上下文切换次数，即由于时间片用完或其他原因被迫切换的次数。



