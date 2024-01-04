# IIS证书管理器导入证书后消失

IIS证书管理器完成证书创建导入证书后消失

这是微软一直以来的BUG，解决方法，将私钥与证书合成为pfx的格式，使用导入按钮来进行证书导入

 

命令：openssl pkcs12 -export -out 导出的pfx文件 -inkey 私钥 -in 证书