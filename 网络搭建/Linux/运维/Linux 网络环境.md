# 网络环境

## ubuntu 24.04 server

```
apt -y install git curl wget tree lrzsz unzip zip vim tar
```



```
apt -y install iproute2 
```



```
apt -y install traceroute dnsutils tcpdump nmap iftop
```



```
apt -y install openvswitch-switch openvswitch-common openvswitch-doc
```



```
apt -y install dnsmasq isc-dhcp-client

systemctl stop dnsmasq
systemctl disable dnsmasq
```



```
vim /etc/sysctl.conf

net.ipv4.ip_forward=1

sysctl -p
```

