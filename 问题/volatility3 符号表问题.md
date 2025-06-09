# volatility3 符号表问题

我获得了一个 Linux 的内存转储文件，以及一个适用于该内存文件，能在 volatility2 中使用的 profile。

我想制作一个适用于该镜像文件的 volatility3 的符号表，于是我使用 vol3 的 banner 功能获取该镜像文件内核的详细信息。

```
vol3 -f linux banner 

Volatility 3 Framework 2.23.0
Progress:  100.00		PDB scanning finished                      
Offset	Banner

0x948001a0	Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)
0x95391d94	Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)
0x13fec78d0	Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)
```



我在 **launchpad.net** 网站上下载了该内核版本的调试内核。

```
https://launchpad.net/ubuntu/bionic/amd64/linux-image-unsigned-5.4.0-84-generic-dbgsym/5.4.0-84.94~18.04.1
```

```
http://launchpadlibrarian.net/555505072/linux-image-unsigned-5.4.0-84-generic-dbgsym_5.4.0-84.94~18.04.1_amd64.ddeb
```

```
linux-image-unsigned-5.4.0-84-generic-dbgsym_5.4.0-84.94~18.04.1_amd64.ddeb
```



我在 Ubuntu 24.04 中使用 dpkg 安装了它。

```
dpkg -i linux-image-unsigned-5.4.0-84-generic-dbgsym_5.4.0-84.94~18.04.1_amd64.ddeb
```



调试内核位于 **/usr/lib/debug/boot/vmlinux-5.4.0-84-generic**，我通过 **dwarf2json** 工具使用以下命令生成符号表。

```
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-5.4.0-84-generic > symbols.json
```



我将内存文件和符号表放置在 /opt/ 路径下，使用一些 volatility3 的插件从内存文件中提取信息，但是失败了。

```
vol3 -f linux -s . linux.bash

Volatility 3 Framework 2.23.0
Progress:  100.00		Stacking attempts finished           
PID	Process	CommandTime	Command

[没有显示任何内容]
```

```
vol3 -f linux -s . linux.sockstat

Volatility 3 Framework 2.23.0
Progress:  100.00		Stacking attempts finished           
NetNS	Process Name	PID	TID	FD	Sock Offset	Family	Type	Proto	Source Addr	Source Port	Destination Addr	Destination PortState	Filter

4026531992	systemd	1	1	9	0x90ee36c24000	AF_NETLINK	RAW	NETLINK_KOBJECT_UEVENT	groups:0x00000002	1	group:0x00000000UNCONNECTED	filter_type=socket_filter,bpf_filter_type=cBPF
4026531992	systemd	1	1	14	0x90ee2ef34000	AF_UNIX	DGRAM	-	/run/systemd/notify	12253	-	-	UNCONNECTED	-
...
4026531992	gdbus	1425	1428	7	0x90ed34d42800	AF_UNIX	STREAM	-	-	41755	/run/user/1000/bus	40826	ESTABLISHED	-

Volatility was unable to read a requested page:
0x13fffffff in layer memory_layer (Invalid address at 13fffffff)

	* The base memory file being incomplete (try re-acquiring if possible)
	* Memory smear during acquisition (try re-acquiring if possible)
	* An intentionally invalid page lookup (operating system protection)
	* A bug in the plugin/volatility3 (re-run with -vvv and file a bug)

No further results will be produced
```



请问我的哪一步出了问题？是调试内核的版本出错了吗？我该如何解决问题？