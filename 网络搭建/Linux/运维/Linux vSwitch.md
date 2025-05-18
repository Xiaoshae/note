# open vSwitch



### vlan id

```
ip netns add vlan10-1
ip netns add vlan10-2


ip link add vlan10-1 type veth peer name eth0 netns vlan10-1
ip link add vlan10-2 type veth peer name eth0 netns vlan10-2


ip link set vlan10-1 up
ip link set vlan10-2 up
```



```
ip netns add vlan20-1
ip netns add vlan20-2

ip link add vlan20-1 type veth peer name eth0 netns vlan20-1
ip link add vlan20-2 type veth peer name eth0 netns vlan20-2

ip link set vlan20-1 up
ip link set vlan20-2 up
```



```
ip link add vlan10-patch type veth peer name vlan20-patch

ip link set vlan10-patch
ip link set vlan20-patch
```



```
ovs-vsctl add-br vlan10

ovs-vsctl add-port vlan10 vlan10-1
ovs-vsctl add-port vlan10 vlan10-2

ovs-vsctl set port vlan10-1 tag=10
ovs-vsctl set port vlan10-2 tag=10

ovs-vsctl add-port vlan10 vlan10-patch
```



```
ovs-vsctl add-br vlan20

ovs-vsctl add-port vlan20 vlan20-1
ovs-vsctl add-port vlan20 vlan20-2

ovs-vsctl set port vlan20-1 tag=20
ovs-vsctl set port vlan20-2 tag=20

ovs-vsctl add-port vlan20 vlan20-patch
```



```
ip netns exec vlan10-1 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.101/24 dev eth0
```



```
ip netns exec vlan10-2 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.102/24 dev eth0
```



```
ip netns exec vlan20-1 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.201/24 dev eth0
```



```
ip netns exec vlan20-2 bash

ip link set lo up
ip link set eth0 up

ip address add 192.168.100.202/24 dev eth0
```



### dhcp

```
apt install -y dnsmasq isc-dhcp-client 
```



```
systemctl stop dnsmasq
```



```
ip netns add dhcp
ip netns add main

ip link add dhcp type veth peer name eth0 netns dhcp
ip link add main type veth peer name eth0 netns main

ip link set dhcp up
ip link set main up

ovs-vsctl add-br br-dhcp
ovs-vsctl add-port br-dhcp dhcp
ovs-vsctl add-port br-dhcp main
```



```
ip netns exec dhcp bash

ip link set lo up
ip link set eth0 up
ip address add 192.168.100.1/24 dev eth0

dnsmasq \
    --no-daemon \
    --interface=eth0 \
    --dhcp-range=192.168.100.100,192.168.100.200,12h \
    --dhcp-option=option:router,192.168.100.1 \
    --dhcp-option=option:dns-server,223.5.5.5,223.6.6.6
dnsmasq: started, version 2.90 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq-dhcp: DHCP, IP range 192.168.100.100 -- 192.168.100.200, lease time 12h
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 127.0.0.53#53
dnsmasq: read /etc/hosts - 8 names
...

# 在 main 命名空间中执行 dhclient eth0 命令后
dnsmasq-dhcp: DHCPDISCOVER(eth0) b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPOFFER(eth0) 192.168.100.195 b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPDISCOVER(eth0) b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPOFFER(eth0) 192.168.100.195 b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPREQUEST(eth0) 192.168.100.195 b6:23:6b:b7:02:36 
dnsmasq-dhcp: DHCPACK(eth0) 192.168.100.195 b6:23:6b:b7:02:36 u4-1
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 127.0.0.53#53
```



```
ip netns exec main bash

ip link set lo up
ip link set eth0 up

dhclient eth0

# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever

2: eth0@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether b6:23:6b:b7:02:36 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.100.195/24 brd 192.168.100.255 scope global dynamic eth0
       valid_lft 42719sec preferred_lft 42719sec
    inet6 fe80::b423:6bff:feb7:236/64 scope link 
       valid_lft forever preferred_lft forever
```

