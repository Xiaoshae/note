![image-20231213180555619](images/Docker%20for%20Windows.assets/image-20231213180555619.png)



```
PS C:\Windows\system32> wsl --export docker-desktop E:\wsl2\docker-desktop\docker-desktop.tar
正在导出，这可能需要几分钟时间。
操作成功完成。
PS C:\Windows\system32> wsl --export docker-desktop-data E:\wsl2\docker-desktop-data\docker-desktop-data.tar
正在导出，这可能需要几分钟时间。
操作成功完成。

PS C:\Windows\system32> wsl --unregister docker-desktop
正在注销。
操作成功完成。
PS C:\Windows\system32> wsl --unregister docker-desktop-data
正在注销。
操作成功完成。


PS C:\Windows\system32> wsl --import docker-desktop  E:\wsl2\docker-desktop E:\wsl2\docker-desktop\docker-desktop.tar
正在导入，这可能需要几分钟时间。
操作成功完成。

PS C:\Windows\system32> wsl --import docker-desktop-data  E:\wsl2\docker-desktop-data E:\wsl2\docker-desktop-data\docker-desktop-data.tar
正在导入，这可能需要几分钟时间。
操作成功完成。
```

