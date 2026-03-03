# acme.sh

## 安装

安装前置依赖：

```
apk add git openssl curl
```



```
git clone https://github.com/acmesh-official/acme.sh.git
cd ./acme.sh
./acme.sh --install -m my@example.com
```



## 配置

将 CA 证书颁发机构修改为 **letsencrypt**

```
acme.sh --set-default-ca --server letsencrypt
```



使用阿里云 DNS 云解析服务完成 ACME 挑战，配置阿里云 DNS 的 AC / AK 。

```
export Ali_Key="xxx"
export Ali_Secret="xxx" 
```



申请颁发证书：

```
./acme.sh --issue --dns dns_ali -d xiaoshae.cn -d "*.xiaoshae.cn" --key-file /docker/sing-box/ssl/xiaoshae.cn/cert.key --fullchain-file /docker/sing-box/ssl/xiaoshae.cn/cert.crt --reloadcmd "docker restart sing-box"  --notify-level 2 --notify-mode 0 --force
```



```
./acme.sh --issue --dns dns_ali -d xiaoshae.cn -d "*.xiaoshae.cn" --key-file /docker/nginx/ssl/xiaoshae.cn/cert.key --fullchain-file /docker/nginx/ssl/xiaoshae.cn/cert.crt --reloadcmd "docker exex nginx nginx -t && docker exec nginx nginx -s reload"  --notify-level 2 --notify-mode 0 --force
```



```
./acme.sh --issue --dns dns_ali -d xiaoshae.cn -d "*.xiaoshae.cn" --key-file /docker/proxy/sing-box/ssl/xiaoshae.cn/cert.key --fullchain-file /docker/proxy/sing-box/ssl/xiaoshae.cn/cert.crt --reloadcmd "docker restart sing-box"  --notify-level 2 --notify-mode 0 --force
```

