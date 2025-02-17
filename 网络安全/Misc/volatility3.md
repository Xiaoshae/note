# volatility3

## windows



## linux



### pslist

```
usage: vol linux.pslist.PsList [-h] [--pid [PID ...]] [--threads] [--decorate-comm] [--dump]

列出特定 Linux 内存镜像中存在的进程。
	
options:
  -h, --help       显示此帮助信息并退出
  --pid [PID ...]  过滤特定的进程 ID
  --threads        包含用户线程
  --decorate-comm  使用花括号显示 用户线程 的 comm，使用方括号显示 内核线程 的 comm
  --dump           提取列出的进程

```



**vol3 -f linux linux.pslist**

```
Volatility 3 Framework 2.19.0   Reconstruction finished

OFFSET (V)	PID	TID	PPID	COMM	UID	GID	EUID	EGID	CREATION TIME	File output

0x9a67c189a900	1	1	0	systemd	0	0	0	0	2025-01-27 09:50:37.317891 UTC	Disabled
0x9a67c1898000	2	2	0	kthreadd	0	0	0	0	2025-01-27 09:50:37.317891 UTC	Disabled
0x9a67c189d200	3	3	2	pool_workqueue_	0	0	0	0	2025-01-27 09:50:37.317891 UTC	Disabled
0x9a67c18b2900	4	4	2	kworker/R-rcu_g	0	0	0	0	2025-01-27 09:50:37.317891 UTC	Disabled
0x9a67c18b0000	5	5	2	kworker/R-rcu_p	0	0	0	0	2025-01-27 09:50:37.317891 UTC	Disabled
0x9a67c18b5200	6	6	2	kworker/R-slub_	0	0	0	0	2025-01-27 09:50:37.317891 UTC	Disabled
```



**vol3 -f linux linux.pslist  --decorate-comm**

```
OFFSET (V)	PID	TID	PPID	COMM	UID	GID	EUID	EGID	CREATION TIME	File output

0x9a67ecff0000	2527	2527	1495	sshd	0	0	0	0	2025-01-27 09:50:51.234594 UTC	Disabled
0x9a67ed552900	2539	2539	1	systemd	0	0	0	0	2025-01-27 09:50:51.361810 UTC	Disabled
0x9a67ecfed200	2542	2542	2539	(sd-pam)	0	0	0	0	2025-01-27 09:50:51.374304 UTC	Disabled
0x9a67ec5c8000	2558	2558	2	[psimon]	0	0	0	0	2025-01-27 09:50:51.558633 UTC	Disabled
0x9a67ebfd2900	2584	2584	2527	bash	0	0	0	0	2025-01-27 09:50:51.875033 UTC	Disabled
```



**vol3 -f linux linux.pslist  --pid 1495 3191**

```
OFFSET (V)	PID	TID	PPID	COMM	UID	GID	EUID	EGID	CREATION TIME	File output

0x9a67d5335200	1495	1495	1	sshd	0	0	0	0	2025-01-27 09:50:46.184541 UTC	Disabled
0x9a67ebfda900	3191	3191	2584	lime	0	0	0	0	2025-01-27 09:51:26.608495 UTC	Disabled
```



### pstree

```
usage: vol linux.pstree.PsTree [-h] [--pid [PID ...]] [--threads] [--decorate-comm]

用于基于父进程ID以树形结构列出进程的插件.

options:
  -h, --help       
  --pid [PID ...]  
  --threads        
  --decorate-comm  
```



**vol3 -f linux linux.pstree**

```
OFFSET (V)	PID	TID	PPID	COMM

0x9a67c189a900	1	1	0	systemd
* 0x9a67d5332900	1386	1386	1	chronyd
** 0x9a67d5bd2900	1391	1391	1386	chronyd
* 0x9a67d4502900	1489	1489	1	cron
* 0x9a67d5335200	1495	1495	1	sshd
** 0x9a67ecff0000	2527	2527	1495	sshd
*** 0x9a67ebfd2900	2584	2584	2527	bash
**** 0x9a67ebfda900	3191	3191	2584	lime
***** 0x9a67f5418000	3192	3192	3191	insmod
* 0x9a67d5bd0000	1500	1500	1	agetty
```



### psscan

```
usage: vol linux.psscan.PsScan [-h]

扫描 Linux 映像中存在的进程

options:
  -h, --help
```



**vol3 -f linux linux.psscan**

```
OFFSET (P)	PID	TID	PPID	COMM	EXIT_STATE

0x1898000	2	2	0	kthreadd	TASK_RUNNING
0x189a900	1	1	0	systemd	TASK_RUNNING
0x189d200	3	3	2	pool_workqueue_	TASK_RUNNING
0x18b0000	5	5	2	kworker/R-rcu_p	TASK_RUNNING
0x18b2900	4	4	2	kworker/R-rcu_g	TASK_RUNNING
0x18b5200	6	6	2	kworker/R-slub_	TASK_RUNNING
0x18b8000	9	9	2	kworker/0:0H	TASK_RUNNING
0x18ba900	8	8	2	kworker/0:0	TASK_RUNNING
0x18bd200	7	7	2	kworker/R-netns	TASK_RUNNING
0x18c0000	12	12	2	kworker/R-mm_pe	TASK_RUNNING
```





### mountinfo

```
usage: vol linux.mountinfo.MountInfo [-h] [--pids [PIDS ...]] [--mntns [MNTNS ...]] [--mount-format]

列出进程挂载命名空间中的挂载点

options:
  -h, --help           显示此帮助信息并退出
  --pids [PIDS ...]    根据特定的进程ID进行过滤。
  --mntns [MNTNS ...]  根据挂载命名空间过滤结果。否则，将显示所有挂载命名空间。
  --mount-format       显示挂载点的简要摘要，输出格式类似于旧的 /proc/[pid]/mounts 或用户态命令 'mount -l'。
```



**vol3 -f linux linux.mountinfo**

```
MNT_NS_ID	MOUNT ID	PARENT_ID	MAJOR:MINOR	ROOT	MOUNT_POINT	MOUNT_OPTIONS	FIELDS	FSTYPE	MOUNT_SRC	SB_OPTIONS

4026531841	38	26	0:20	/	/dev/mqueue	rw,nosuid,nodev,noexec,relatime	shared:15	mqueue	mqueue	rw
4026531841	30	24	0:6	/	/sys/kernel/security	rw,nosuid,nodev,noexec,relatime	shared:8	securityfs	securityfs	rw
4026531841	26	29	0:5	/	/dev	rw,nosuid,relatime	shared:2	devtmpfs	udev	rw
4026531841	24	29	0:22	/	/sys	rw,nosuid,nodev,noexec,relatime	shared:7	sysfs	sysfs	rw
4026531841	1	1	0:2	/	/	rw		rootfs	rootfs	rw
```



**vol3 -f linux linux.mountinfo --mount-format**

```
MNT_NS_ID	DEVNAME	PATH	FSTYPE	MNT_OPTS

4026531841	mqueue	/dev/mqueue	mqueue	noexec,relatime,nosuid,rw,nodev
4026531841	securityfs	/sys/kernel/security	securityfs	noexec,relatime,nosuid,rw,nodev
4026531841	udev	/dev	devtmpfs	nosuid,rw,relatime
4026531841	sysfs	/sys	sysfs	noexec,relatime,nosuid,rw,nodev
4026531841	rootfs	/	rootfs	rw
```



### bash

```
usage: vol linux.bash.Bash [-h] [--pid [PID ...]]

从内存中恢复 bash 命令历史记录。

options:
  -h, --help       显示此帮助信息并退出
  --pid [PID ...]  要包含的进程 ID（其他进程将被排除）	
```



**vol3 -f linux linux.mountinfo**

```
PID	Process	CommandTime	Command

2584	bash	2025-01-27 09:50:53.000000 UTC	ip a
2584	bash	2025-01-27 09:50:53.000000 UTC	init 0
2584	bash	2025-01-27 09:50:53.000000 UTC	ls
2584	bash	2025-01-27 09:50:53.000000 UTC	docker kill vol2 
2584	bash	2025-01-27 09:50:53.000000 UTC	docker rm vol2 
2584	bash	2025-01-27 09:50:53.000000 UTC	ls
2584	bash	2025-01-27 09:50:53.000000 UTC	docker compose up -d 
2584	bash	2025-01-27 09:50:53.000000 UTC	vi compose.yaml 
2584	bash	2025-01-27 09:50:53.000000 UTC	docker compose up -d 
2584	bash	2025-01-27 09:50:53.000000 UTC	ip a
2584	bash	2025-01-27 09:50:53.000000 UTC	ls
```



### boottime

显示系统启动时间



**vol3 -f linux linux.boottime**

```
Progress:  100.00		Reconstruction finished
TIME NS	Boot Time

4026531834	2025-01-27 09:50:37.966637 UTC
```



### capabilities

列出进程的权限（capabilities）

```
options:
  -h, --help         显示此帮助信息并退出
  --pids [PIDS ...]  根据特定的进程 ID 进行过滤。
```



**vol3 -f linux linux.capabilities**

```
Name	Tid	Pid	PPid	EUID	cap_inheritable	cap_permitted	cap_effective	cap_bounding	cap_ambient

systemd	1	1	0	0		all	all	all	
kthreadd	2	2	0	0		all	all	all	
pool_workqueue_	3	3	2	0		all	all	all	
kworker/R-rcu_g	4	4	2	0		all	all	all	
kworker/R-rcu_p	5	5	2	0		all	all	all	
kworker/R-slub_	6	6	2	0		all	all	all	
```



### check_afinfo

验证网络协议的操作函数指针



**vol3 -f linux linux.check_afinfo**

```
Symbol Name	Member	Handler Address
WARNING  volatility3.plugins.linux.check_afinfo: This plugin was not able to check for hooks. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt.
```

**警告 volatility3.plugins.linux.check_afinfo：此插件无法检查钩子。这意味着您正在分析不受支持的内核版本，或者您的符号表已损坏。**



### check_creds

检查是否有任何进程正在共享凭证结构



**vol3 -f linux linux.check_creds**

```
CredVAddr	PIDs
```

**无内容**



### check_idt

检查 IDT 是否已被改变



**vol3 -f linux linux.check_idt**

```
Index	Address	Module	Symbol

0x0	0xffff9de00950	__kernel__	asm_exc_divide_error
0x1	0xffff9de00c90	__kernel__	asm_exc_debug
0x2	0xffff9de01720	__kernel__	asm_exc_nmi
0x3	0xffff9de00b60	__kernel__	asm_exc_int3
```



### check_modules

将模块列表与 sysfs 信息进行比较（如果可用）



**vol3 -f linux linux.check_modules**

```
Module Address	Module Name

0xffffc0f47040	vmw_vsock_virtio_transport_commo
```





### check_syscall

检查系统调用表中是否存在钩子



**vol3 -f linux linux.check_syscall**

```
Table Address	Table Name	Index	Handler Address	Handler Symbol

0xffff82600320	64bit	0	0xffff9cee5d40	__x64_sys_read
0xffff82600320	64bit	1	0xffff9cee5ed0	__x64_sys_write
0xffff82600320	64bit	2	0xffff9cee0d60	__x64_sys_open
0xffff82600320	64bit	3	0xffff9ceddb20	__x64_sys_close
0xffff82600320	64bit	4	0xffff9ceee1a0	__x64_sys_newstat
0xffff82600320	64bit	5	0xffff9ceedd50	__x64_sys_newfstat
```



### ebpf

枚举 eBPF 程序



**vol3 -f linux linux.ebpf**

```
Address	Name	Tag	Type

0xb5500006d000	hid_tail_call	7cc47bbf07148bfe	BPF_PROG_TYPE_TRACING
0xb55000669000	sd_devices	c8b47a902f1cc68b	BPF_PROG_TYPE_CGROUP_DEVICE
0xb55000751000	sd_devices	e3dbd137be8d6168	BPF_PROG_TYPE_CGROUP_DEVICE
0xb55000771000	sd_fw_egress	6deef7357e7b4530	BPF_PROG_TYPE_CGROUP_SKB
```



### elfs

```
用法: vol linux.elfs.Elfs [-h] [--pid [PID ...]] [--dump]

列出所有进程的内存映射 ELF 文件。

选项:
  -h, --help       显示此帮助信息并退出
  --pid [PID ...]  根据特定的进程 ID 进行过滤
  --dump           提取列出的进程
```



**vol3 -f linux linux.elfs**

```
PID	Process	Start	End	File Path	File Output

1	systemd	0x61738ae95000	0x61738ae9b000	/usr/lib/systemd/systemd	Disabled
1	systemd	0x7f2f18966000	0x7f2f18968000	/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2	Disabled
1	systemd	0x7f2f18a00000	0x7f2f18ab3000	/usr/lib/x86_64-linux-gnu/libcrypto.so.3	Disabled
1	systemd	0x7f2f18f7d000	0x7f2f18f81000	/usr/lib/x86_64-linux-gnu/libgpg-error.so.0.34.0	Disabled
1	systemd	0x7f2f18fa2000	0x7f2f18fa4000	/usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0	Disabled
```



### envars

```
用法: vol linux.envars.Envars [-h] [--pid [PID ...]]

列出进程及其环境变量。

选项:
  -h, --help       显示此帮助信息并退出
  --pid [PID ...]  根据特定的进程 ID 进行过滤
```



**vol3 -f linux linux.envars**

```
PID	PPID	COMM	KEY	VALUE

1	0	systemd	HOME	/
1	0	systemd	init	/sbin/init
1	0	systemd	NETWORK_SKIP_ENSLAVED	
1	0	systemd	TERM	linux
```



### fbdev

```
用法: vol linux.graphics.fbdev.Fbdev [-h] [--dump]

从 fbdev 图形子系统中提取帧缓冲区。

选项:
  -h, --help  显示此帮助信息并退出
  --dump      提取帧缓冲区
```



**vol3 -f linux linux.graphics**

```
Address	Device	ID	Size	Virtual resolution	BPP	State	Filename

0xb55002001000	fb0	vmwgfxdrmfb	4096000	1280x800	32	RUNNING	Disabled
```



### hidden_modules

通过扫描内存来查找隐藏的内核模块。



**vol3 -f linux linux.hidden_modules**

```
Address	Name


```

**无内容**



