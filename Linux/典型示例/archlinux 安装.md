# archlinux 安装

首先，您需要找到正确的硬盘设备路径。使用 `fdisk -l` 命令列出所有块设备，并找到您想要分区的硬盘。

```
fdisk -l
```

例如，如果您的硬盘是 `/dev/sda`，那么在接下来的步骤中就使用这个路径。



使用 fdisk 创建分区

```
fdisk /dev/sda
```



现在，您将进入 `fdisk` 交互式命令行界面。按照以下步骤创建分区：

**创建新的 GPT 分区表**:

- 输入 `g`，然后按 Enter。
- 这将创建一个新的空 GPT 分区表。

**创建 EFI 系统分区 (ESP)**:

- 输入 `n`，然后按 Enter 创建新分区。
- 系统会提示您选择分区号。选择 `1`，然后按 Enter。
- 系统会提示您选择第一个扇区。直接按 Enter 使用默认值。
- 系统会提示您选择最后一个扇区。输入 `+1G`（表示分区大小为 1 GiB），然后按 Enter。
- 输入 `t`，然后按 Enter，选择分区类型。
- 输入 `1`，然后按 Enter，将分区类型设置为 **EFI System**。

**创建根分区 (`/`)**:

- 输入 `n`，然后按 Enter 创建第二个新分区。
- 选择分区号 `2`，然后按 Enter。
- 系统会提示您选择第一个扇区。直接按 Enter 使用默认值。
- 系统会提示您选择最后一个扇区。直接按 Enter 使用所有剩余的可用空间。
- 输入 `t`，然后按 Enter，选择分区类型。
- 选择分区号 `2`，然后按 Enter。
- 输入 `23`，然后按 Enter，将分区类型设置为 **Linux root (x86-64)**。

**保存并退出**:

- 输入 `w`，然后按 Enter，将更改写入磁盘并退出 `fdisk`。



格式化分区

创建分区后，您需要对它们进行格式化。

**格式化 EFI 系统分区**: 使用 `mkfs.fat` 命令将第一个分区格式化为 FAT32。

```
mkfs.fat -F 32 /dev/sda1
```



**格式化根分区**：

使用 `mkfs.ext4` 命令将第二个分区格式化为 Ext4。

```
mkfs.ext4 /dev/sda2
```



挂载分区

最后，将新格式化的分区挂载到文件系统。

```
# mount /dev/sda2 /mnt
```



**创建并挂载 EFI 系统分区**：

在 `/mnt` 中创建一个 **/boot** 目录，然后将 EFI 系统分区 (`/dev/sda1`) 挂载到该目录。

```
# mount --mkdir /dev/sda1 /mnt/boot
```



### 1. 安装基本系统和软件包



首先，确保您的镜像源配置正确。在 `/etc/pacman.d/mirrorlist` 文件中，将离您地理位置最近的镜像源放在文件顶部，以获得更快的下载速度。

要在 `/etc/pacman.d/mirrorlist` 中配置清华大学开源软件镜像站，您需要编辑该文件，并将清华大学镜像站的 URL 放在文件的开头。

**编辑 `/etc/pacman.d/mirrorlist` 文件**

在终端中使用一个文本编辑器（如 `vim`）打开文件。如果您之前安装了 `vim`，可以使用以下命令：

```
vim /etc/pacman.d/mirrorlist
```



添加清华大学镜像站

在文件的最顶部，添加以下两行，以确保 pacman 优先使用清华大学的镜像源：

```
## TUNA Tsinghua University Mirror
Server = https://mirrors.tuna.tsinghua.edu.cn/archlinux/$repo/os/$arch
```

保存并关闭文件。在 `vim` 中，您可以按 `Esc` 键，然后输入 `:wq` 并按 `Enter` 来保存并退出。



同步软件包数据库

配置完成后，运行 `pacman -Sy` 命令来同步新的镜像源的软件包数据库：

```
pacman -Sy
```



然后，使用 `pacstrap` 脚本安装核心软件包、Linux 内核和固件。为了确保系统的完整性，建议同时安装一些必要的工具，例如文本编辑器 `vim`。

```
# pacstrap -K /mnt base linux linux-firmware vim
```

如果您使用的是 Intel 或 AMD 的 CPU，建议安装相应的微码包：

- **Intel CPU**: `pacstrap -K /mnt intel-ucode`
- **AMD CPU**: `pacstrap -K /mnt amd-ucode`



生成 fstab 文件

`fstab` 文件负责在系统启动时自动挂载分区。使用 `genfstab` 命令生成此文件，并将其输出重定向到 `/mnt/etc/fstab`。强烈建议在生成后立即检查文件内容，确保分区信息正确。

```
genfstab -U /mnt >> /mnt/etc/fstab
```



进入新系统环境 (chroot)

`arch-chroot` 命令让您进入新安装的系统，就像在已安装的系统中操作一样。

```
# arch-chroot /mnt
```

进入 chroot 环境后，所有操作都将直接影响到新系统。



系统配置

在 chroot 环境中，您需要完成以下配置：

设置时区

将系统时区设置为您所在地区。例如，对于中国大陆，时区应设置为上海。

```
# ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
```



接着，同步硬件时钟。

```
# hwclock --systohc
```



**区域和本地化**

编辑 `/etc/locale.gen` 文件，取消您需要的语言区域设置（例如 `en_US.UTF-8`）前面的注释。

```
# locale-gen
```

然后，创建 `/etc/locale.conf` 文件并设置 `LANG` 变量。为了方便查看系统日志，建议设置为 `en_US.UTF-8`。

```
# echo "LANG=en_US.UTF-8" > /etc/locale.conf
```



网络配置

为您的计算机设置主机名，并创建一个 /etc/hostname 文件。

```
# echo "您的主机名" > /etc/hostname
```



设置 Root 密码

使用 passwd 命令为 root 用户设置一个强密码。

```
passwd root
```



安装引导程序

引导程序是系统启动的关键。**GRUB** 是一个通用且常见的选择。请按照以下步骤安装 GRUB：

安装 GRUB:

```
# pacman -S grub efibootmgr
```



安装 GRUB 到 EFI 分区:

```
# grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
```



生成 GRUB 配置文件:

```
# grub-mkconfig -o /boot/grub/grub.cfg
```

**警告**: 这是最关键的一步。如果引导程序安装或配置不正确，您的系统将无法启动。



重启系统

完成所有配置后，输入 `exit` 退出 chroot 环境。

```
# exit
```

最后，使用 `reboot` 命令重启计算机，并在重启时移除安装介质。

```
# reboot
```

