# Linux CA证书服务器为所有Linux主机颁发证书

1.搭建CA根证书环境

```shell
[root@linux ~]# dnf -y install openssl*
[root@linux ~]# cd /etc/pki/CA/
[root@linux CA]# openssl genrsa -out private/cakey.pem 2048
[root@linux CA]# openssl req -new -x509 -key private/cakey.pem -out cacert.pem -days 7300
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:CN
State or Province Name (full name) []:Beijing
Locality Name (eg, city) [Default City]:Beijing
Organization Name (eg, company) [Default Company Ltd]:Skills
Organizational Unit Name (eg, section) []:System
Common Name (eg, your name or your server's hostname) []:skills.com
Email Address []:
[root@linux CA]# touch index.txt
[root@linux CA]# echo 01 > serial
[root@linux CA]# tree
.
├── cacert.pem
├── certs
├── crl
├── index.txt
├── newcerts
├── private
│   └── cakey.pem
└── serial

4 directories, 4 files
```

步骤：生成私钥，依据私钥创建公钥申请，创建dns扩展文件，CA机构颁发证书，将私钥和证书复制到Linux目录，删除本地保留

```shell
[root@linux work]# openssl genrsa -out skills.key 2048
[root@linux work]# openssl req -new -key skills.key -out skills.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Skills/OU=System/CN=linux1.skills.com"
[root@linux work]# echo -e "subjectAltName=@alt_names\n[alt_names]\nDNS.1=linux1.skills.com" > dns.extfile
[root@linux work]# openssl ca -in skills.csr -out skills.crt -extfile dns.extfile -days 3650 
Using configuration from /etc/pki/tls/openssl.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 1 (0x1)
        Validity
            Not Before: Feb 18 23:22:44 2023 GMT
            Not After : Feb 15 23:22:44 2033 GMT
        Subject:
            countryName               = CN
            stateOrProvinceName       = Beijing
            organizationName          = Skills
            organizationalUnitName    = System
            commonName                = linux1.skills.com
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:linux1.skills.com
Certificate is to be certified until Feb 15 23:22:44 2033 GMT (3650 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Data Base Updated
[root@linux work]# scp skills.key root@10.10.20.101:/etc/ssl/skills.key
[root@linux work]# scp skills.crt root@10.10.20.101:/etc/ssl/skills.crt
[root@linux work]# rm -rf skills.*
```

编写shell脚本自动部署CA证书

```shell
#!/bin/bash
HostFile="hostall.txt"
for((i=1;$i<=7;i++));
do
	HostIP=`sed -n "$i,$i p" $HostFile`
	openssl genrsa -out skills.key 2048
	openssl req -new -key skills.key -out skills.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Skills/OU=System/CN=linux$i.skills.com"
	echo -e "subjectAltName=@alt_names\n[alt_names]\nDNS.1=linux$i.skills.com" > dns.extfile
	openssl ca -in skills.csr -out skills.crt -extfile dns.extfile -days 3650
	scp -o StrictHostKeyChecking=no  skills.key root@$HostIP:/etc/ssl/skills.key
	scp -o StrictHostKeyChecking=no  skills.crt root@$HostIP:/etc/ssl/skills.crt
	rm -rf skills.*
done
```

# Linux所有主机信任根CA证书

添加证书到受信任的证书脚本

```
#!/bin/bash
cat $1 >> /etc/pki/tls/certs/ca-bundle.crt
cp $1 /etc/pki/ca-trust/source/anchors/
```

分发脚本和根证书到所有Linux主机并添加到运行脚本

```
#！/bin/bash
HostFile="hostall.txt"
for((i=2;$i<=7;i++));
do
        HostIP=`sed -n "$i,$i p" $HostFile`
        sshpass -p Pass-1234 scp -o StrictHostKeyChecking=no /root/cacert.pem root@$HostIP:/root/cacert.pem
        sshpass -p Pass-1234 scp -o StrictHostKeyChecking=no /root/addcert.sh root@$HostIP:/root/addcert.sh
        sshpass -p Pass-1234 ssh -o StrictHostKeyChecking=no root@$HostIP "/root/addcert.sh cacert.pem"
done
```

