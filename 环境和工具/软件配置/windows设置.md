# Windows 设置

## 保留的存储

在 Windows 中，「保留的存储」（Reserved Storage）是指 Windows 操作系统在系统分区（通常是 C 盘）上预留的一部分存储空间。该空间会用于存储临时文件、缓存文件、系统更新文件等。

说直白一点就是：先打一个提前量，以免要用的时候，系统分区的可用空间不足。



一般情况下不推荐关闭此功能，因为禁用可能导致 Windows 更新失败或系统运行不稳定。如果确实有需要，可以通过以下方法查看容量或直接禁用。



1. 使用`Windows + I`快捷键打开「Windows 设置」。

2. 导航到「系统」-「存储」，然后点击「显示更多类别」。

![点击显示更多类别](./images/windows%E8%AE%BE%E7%BD%AE.assets/windows-reserved-storage-p5.jpg)

3. 在展开的列表中点击「系统和保留」选项。
4. 在新打开的页面中即可查看到用量。

![查看保留的存储](./images/windows%E8%AE%BE%E7%BD%AE.assets/windows-reserved-storage-p6.jpg)



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

![img](./images/windows%E8%AE%BE%E7%BD%AE.assets/windows-reserved-storage-p7.jpg)

4. 重启计算机。
5. （可选）如果有需要，可以随时使用以下命令再次启用。

```
dism /Online /Set-ReservedStorageState /State:Enabled
```



## 隐藏“此电脑”窗口中的“桌面”选项

Windows10 中打开此电脑后，顶级菜单不是“此电脑”而是“桌面”，修改回来。

![img](./images/windows%E8%AE%BE%E7%BD%AE.assets/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20240602200116.png)



在 Windows 10 中，如果您想要隐藏“此电脑”窗口中的“桌面”选项，请按照以下步骤操作：

1. 打开任意一个文件资源管理器窗口（快捷键：Win+E）。
2. 在顶部的菜单栏中找到并点击“查看”选项。
3. 在下拉菜单中选择“选项”，这将打开一个新的对话框。

![image-20240602200557837](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20240602200557837.png)

4. 在新打开的“文件夹选项”或“文件资源管理器选项”对话框中，切换到“查看”标签页。

5. 在高级设置部分向下滚动，直到您看到“导航窗格”下的选项。
6. 找到名为“显示‘库’和每个驱动器的根目录”的复选框，并取消勾选它。

7. 点击底部的“应用”按钮，然后点击“确定”。

![image-20240602200718417](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20240602200718417.png)



最后的效果：
![image-20240602200748683](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20240602200748683.png)



## Bitlocker 等待激活

BitLocker 的“等待激活”状态是指 BitLocker 已启用，但加密过程尚未开始，磁盘未被完全加密。此状态下，系统已为 BitLocker 配置了保护措施（如 TPM 或密码），但实际的加密操作被推迟，数据仍未受到完整保护。



在 Bitlocker 管理中呈现出以下状态：

![win10电脑提示bitlocker正在等待激活的原因和解决方法](./images/windows%E8%AE%BE%E7%BD%AE.assets/fcadaff30ae09517f8364a9a1c50c9b2.jpeg)



在 CMD 中输入以下命令，禁用 Bitlocker 即可解决：

```
manage-bde -off C:
```



## 完全关闭 hyper-v

Windows 的 Hyper-V 和 VMware 都使用 CPU 的硬件虚拟化扩展（如 Intel VT-x 或 AMD-V），两者无法同时运行。

在 Windows 10 和 11（包括家庭版、专业版和企业版）中完全禁用 Hyper-V，以允许 VMware（特别是嵌套虚拟化）正常运行。



首先，检查 **BIOS** 中是否开启了硬件虚拟化。在 Windows 中，打开**任务管理器**，切换到**性能**中的 **CPU** 窗口，查看**虚拟化**字段是否显示 **已启用**。

如果显示**已启用**，则表明硬件层面支持虚拟化，但 **VMware** 无法启用嵌套虚拟化可能是软件（操作系统）问题。如果显示**未启用**，则大概率为硬件问题，需要在 **BIOS** 中启用硬件虚拟化选项。目前，绝大多数台式机和笔记本在 **BIOS** 中默认启用硬件虚拟化。

![image-20250428190812424](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428190812424.png)



软件（操作系统）问题中，**绝大多数**是由于 **Windows 系统**直接或间接启用了 **Hyper-V**，因此需要通过多种方法**完全禁用 Hyper-V**。



1. 关闭 Windows 功能

打开**控制面板**，导航至**程序和功能**，然后点击**打开或关闭 Windows 功能**。取消选中 **Hyper-V**、**虚拟机平台** 和 **Windows 虚拟机监控程序平台**。点击**确定**，并根据提示重启计算机。

![image-20250428191132027](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428191132027.png)

![image-20250428191203659](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428191203659.png)

![image-20250428191300993](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428191300993.png)



	2. 使用 BCDEdit 禁用 Hyper-V：

**以管理员身份**打开**命令提示符**（按 Win + X，选择“命令提示符（管理员）”）。输入命令：**bcdedit /set hypervisorlaunchtype off** 并按回车。最后，重启计算机以应用更改。

```
bcdedit /set hypervisorlaunchtype off
```

![image-20250428192734010](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428192734010.png)

![image-20250428191531158](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428191531158.png)



3. 禁用核心隔离中的内存完整性：

首先，打开 **Windows 安全中心**，然后导航到**设备安全** > **核心隔离**。接下来，关闭**内存完整性**开关。**最后，重启计算机**以应用更改。

![image-20250428192002325](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428192002325.png)



**验证 Hyper-V 已完全禁用**

首先，按 **Win + R** 组合键打开运行对话框，然后输入 **msinfo32.exe** 并按回车。在“系统信息”窗口中，检查是否显示 **“检测到虚拟机监控程序。Hyper-V 所需的功能将不显示。”** 如果没有此提示，则说明 **Hyper-V 已成功禁用**。



如果显示的界面如以下图片所示，则表示 **Hyper-V 已启用（未完全禁用）**。

![image-20250428192235526](./images/windows%E8%AE%BE%E7%BD%AE.assets/image-20250428192235526.png)



如果显示的界面如以下图片所示，则表示 **Hyper-V 已禁用**。
