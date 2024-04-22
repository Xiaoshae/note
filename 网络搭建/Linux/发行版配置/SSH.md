# linux 常用配置



# SSH基本配置

端口：

```
Port 22
Port 234
```

监听地址：

```
ListenAddress 0.0.0.0
ListenAddress ::
```

允许root登录：

```
PermitRootLogin yes
```

允许**密码**登录：

```
PasswordAuthentication yes
```

允许**密钥**登录：

```
PubkeyAuthentication yes
```

设置**密钥的位置**：

```
AuthorizedKeysFile ~/.ssh/authorized_keys ~/.ssh/authorized_keys_2
```





# ssh心跳

在连接远程SSH服务的时候，经常会发生长时间后的断线，或者无响应（无法再键盘输入）。

## 一、客户端定时发送心跳

1.putty、SecureCRT、XShell都有这个功能，设置请自行搜索

2.此外在Linux下，编辑**ssh**_config：

```bash
#修改本机/etc/ssh/ssh_config
vim /etc/ssh/ssh_config
```

\# 添加

```bash
ServerAliveInterval 30
ServerAliveCountMax 100
```

即每隔30秒，向服务器发出一次心跳。若超过100次请求，都没有发送成功，则会主动断开与服务器端的连接。



## 二、服务器端定时向客户端发送心跳（一劳永逸）

\# 修改服务器端 ssh配置 /etc/ssh/**sshd**_config

```bash
vim /etc/ssh/sshd_config
```

\# 添加

```bash
ClientAliveInterval 3
ClientAliveCountMax 6
```

`ClientAliveInterval`表示每隔多少秒，服务器端向客户端发送心跳，是的，你没看错。

下面的`ClientAliveInterval`表示上述多少次心跳无响应之后，会认为Client已经断开。

所以，总共允许无响应的时间是60*3=180秒。
