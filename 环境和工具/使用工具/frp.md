# 端口映射

frps

```
bindAddr = "0.0.0.0"
bindPort = 35535

auth.method = "token"
auth.token = "GuangDong-HongKong"

log.to = "./frps.log"
log.level = "info"
log.maxDays = 0
log.disablePrintColor = false

```



frpc hongkong

```
serverAddr = "8.134.209.140"
serverPort = 35535

auth.method = "token"
auth.token = "GuangDong-HongKong"

log.to = "./frpc.log"
log.level = "info"
log.maxDays = 0
log.disablePrintColor = false


[[proxies]]
name = "sing-box"
type = "tcp"
localIP = "127.0.0.1"
localPort = 40004
remotePort = 40004

```



frpc 新加坡

```
serverAddr = "8.134.209.140"
serverPort = 35535

auth.method = "token"
auth.token = "GuangDong-HongKong"

log.to = "./frpc.log"
log.level = "info"
log.maxDays = 0
log.disablePrintColor = false


[[proxies]]
name = "mc-tcp"
type = "tcp"
localIP = "35.198.199.100"
localPort = 65535
remotePort = 65535

[[proxies]]
name = "mc-udp"
type = "udp"
localIP = "35.198.199.100"
localPort = 65535
remotePort = 65535
```

