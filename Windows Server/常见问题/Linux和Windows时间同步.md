# Windows与Linux时间同步

Windows与Linux的时间同步需要完成， 否则会出现一些问题，例如证书有效期的问题

 

解决方法：Linux 搭建时间服务器Chronyd，将Windows的网段加入的允许的网段。然后将Windows域控制器（Windows中的时间服务器）的时间服务器设置为Linux的时间服务器。

 

具体命令：w32tm /config /manualpeerlist:"xx.xx.xx.xx " /syncfromflags:manual /reliable:yes /update 



然后在其他Windows上输入命令，立即与Windows的时间服务器同步时间：w32tm /resync