# DHCP

安装DHCP：`dnf -y install dhcp-server`

```
subnet [网络号] netmask [子网掩码] {
  range [起始IP] [结束IP];
  option domain-name-servers [域名IP];
  option routers [网关IP];
  option broadcast-address [广播IP];
  default-lease-time 600;
  max-lease-time 7200;
}

```

保留IP地址：

```
host fantasia {
  hardware ethernet [MAC地址];
  fixed-address [保留的IP地址];
}
```



---

```
subnet 192.168.27.0 netmask 255.255.255.0 {
  range 192.168.27.100 192.168.27.120;
  range 192.168.27.200 192.168.27.220;
  option domain-name-servers 192.168.27.254;
  option routers 192.168.27.254;
  option broadcast-address 192.168.27.255;
  default-lease-time 600;
  max-lease-time 7200;
}
```

```
host fantasia {
  hardware ethernet 00:0c:29:90:7d:47;
  fixed-address 192.168.27.110;
}
```

