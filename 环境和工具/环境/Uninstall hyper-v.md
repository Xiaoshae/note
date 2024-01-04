# 完全卸载hyper-v

注意：操作hyper-v会影响到wsl，极大可能导致wsl不可以用。解决方法是：提前备份wsl，卸载hyper-v后，根据步骤完全卸载wsl，然后在根据步骤安装wsl。



取消hyper-v勾选，确定，然后重启系统



![img](images/Uninstall%20hyper-v.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxODkwMjA5,size_16,color_FFFFFF,t_70.png)

powershell管理员权限执行以下命令。遇到不能执行的直接跳过，全部执行完毕后重启系统。

```
Dism /online /disable-feature /featurename:Microsoft-Hyper-V-All /Remove

Dism /Online /Cleanup-Image /RestoreHealth Dism.exe /online /Cleanup-Image /StartComponentCleanup sfc /scannow 

Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All 

Dism /Online /Cleanup-Image /RestoreHealth 

Dism.exe /online /Cleanup-Image /StartComponentCleanup 

bcdedit /set hypervisorlaunchtype off

Dism /Online /Cleanup-Image /ScanHealth

Dism /Online /Cleanup-Image /CheckHealth

DISM /Online /Cleanup-image /RestoreHealth

sfc /SCANNOW
```

