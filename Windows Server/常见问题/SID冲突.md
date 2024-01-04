# SID冲突问题

SID是Windows用来识别账户的标志。Vmware现有的克隆虚拟机是把整个安装好的系统分区直接克隆下来，多台机器拥有相同的SID，有可能发生SID冲突问题。



![img](images/SID%E5%86%B2%E7%AA%81.assets/153882-20190501150702942-1863605890.png)



1.运行系统盘符（默认为C盘）windows/System32/Sysprep/Sysprep.exe程序（以管理员权限）。

2.PowerShell(以管理员权限)命令行模式：

```powershell
cd C:\Windows\System32\Sysprep\
Sysprep /generalize /reboot /oobe
```

![img](images/SID%E5%86%B2%E7%AA%81.assets/20161205174541194.png)
