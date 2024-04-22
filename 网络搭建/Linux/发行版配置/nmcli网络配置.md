# RockyLinux9.0网络配置

CentOS Stream 9网卡配置文件的位置变换了位置，新位置：/etc/NetworkManager/system-connections



1.使用DHCP动态分配IP地址的网卡，在此目录下可能没有配置文件，使用nmcli创建配置文件

`nmcli connection add con-name ens3 ifname ens3 type ethernet autoconnect yes`



2.使用nmcli给编辑配置文件，设置IP地址、子网掩码、网关和DNS

`nmcli connection modify ens3 ipv4.addresses xx.xx.xx.xx/xx ipv4.gateway xx.xx.xx.xx ipv4.dns "xx.xx.xx.xx xx.xx.xx.xx"`



3.重启整个网络使配置文件生效

`nmcli connection reload && nmcli networking off && nmcli networking on`



# Shell批量操作

编写shell脚本自动化部署所有Linux主机的网卡配置

```shell
#！/bin/bash
HostFile="hostall.txt"
for((i=1;$i<=7;i++));
do
	HostIP=`sed -n "$i,$i p" $HostFile`
	sshpass -p Pass-1234 ssh -o StrictHostKeyChecking=no root@$HostIP "nmcli connection add con-name ens3 ifname ens3 type ethernet autoconnect yes"
	sshpass -p Pass-1234 ssh -o StrictHostKeyChecking=no root@$HostIP "nmcli connection modify ens3 ipv4.addresses $HostIP/24 ipv4.gateway 10.10.20.254 ipv4.dns \"10.10.20.101 10.10.20.102\""
	sshpass -p Pass-1234 ssh -o StrictHostKeyChecking=no root@$HostIP "nmcli connection reload && nmcli networking off && nmcli networking on"
done
```

