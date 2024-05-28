# 保留的存储

在 Windows 中，「保留的存储」（Reserved Storage）是指 Windows 操作系统在系统分区（通常是 C 盘）上预留的一部分存储空间。该空间会用于存储临时文件、缓存文件、系统更新文件等。

说直白一点就是：先打一个提前量，以免要用的时候，系统分区的可用空间不足。



一般情况下不推荐关闭此功能，因为禁用可能导致 Windows 更新失败或系统运行不稳定。如果确实有需要，可以通过以下方法查看容量或直接禁用。



1. 使用`Windows + I`快捷键打开「Windows 设置」。

2. 导航到「系统」-「存储」，然后点击「显示更多类别」。

![点击显示更多类别](https://img.sysgeek.cn/img/2023/12/windows-reserved-storage-p5.jpg)

3. 在展开的列表中点击「系统和保留」选项。
4. 在新打开的页面中即可查看到用量。

![查看保留的存储](https://img.sysgeek.cn/img/2023/12/windows-reserved-storage-p6.jpg)



## 关闭保留的存储

我们可以使用 DISM 命令来禁用保留的存储，操作步骤如下：

1. 使用`Windows + R`快捷键打开「运行」，输入`cmd`，然后按`Ctrl + Shift + Enter`以管理员权限打开「命令提示符」。

2. 执行以下命令，可以查看启用状态：

```
dism /Online /Get-ReservedStorageState
```

3. 可以执行以下命令将其禁用：

```
dism /Online /Set-ReservedStorageState /State:Disabled
```

![img](https://img.sysgeek.cn/img/2023/12/windows-reserved-storage-p7.jpg)

4. 重启计算机。
5. （可选）如果有需要，可以随时使用以下命令再次启用。

```
dism /Online /Set-ReservedStorageState /State:Enabled
```

