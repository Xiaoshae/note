# ubuntu 系统安装

示例镜像：ubuntu-24.04.3-live-server-amd64.iso



## 选择语言

**语言选择界面**

使用键盘上的**上（UP）**、**下（DOWN）**箭头键来移动光标，选择您想要的语言（目前高亮显示的是 "English"），然后按**回车键（ENTER）**来确认选择。

![image-20251029182125815](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029182125815.png)



## 选择键盘布局

**键盘配置（Keyboard configuration）界面**

请在选择您的键盘布局，或者选择“识别键盘”来自动检测您的布局。

![image-20251029183650336](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029183650336.png)

**Layout (布局):** 这是主要的键盘布局类型。默认选中的是“美国英语”布局，这是最常见的 QWERTY 键盘布局。

**Variant (变体):** 这是布局的子类型或变体。

**[ Identify keyboard ] (识别键盘): ** 如果您不确定自己的键盘是哪种布局，可以选择此选项，安装程序可能会通过让您按几个键来尝试自动识别。

**[ Done ] (完成)**

**[ Back ] (返回)**

如果使用的是最常见的标准键盘（美式键盘），直接选择 **[ Done ]**（完成）按回车键即可。



“键盘布局”是一个**软件设置**，它定义了**您键盘上的物理按键**与**电脑屏幕上出现的字符**之间的对应关系。

简单来说，它定义 “当用户按下这个键时，应该输入'A'；当用户按下那个键时，应该输入'!'。”



**不同国家和地区使用的键盘并不完全相同**

**最常见的例子：QWERTY vs AZERTY**

- **QWERTY 布局**：这是我们在中国、美国和全球大多数地方使用的标准布局。键盘左上角的字母是 Q、W、E、R、T、Y。以上截图中选择的 `English (US)`（美国英语）就是这种布局。
- **AZERTY 布局**：这是法国等国家使用的布局。他们的键盘左上角是 A、Z、E、R、T、Y。
- **QWERTZ 布局**：这是德国等国家使用的布局，Z 和 Y 键是互换的。



**不同类型的键盘，符号位置不同**

即使是字母相同，不同布局的**符号位置**也可能完全不同。

- 在 `English (US)`（美国）布局上，`Shift + 2` 通常是 `@` 符号。
- 在 `English (UK)`（英国）布局上，`Shift + 2` 可能是 `"` 符号（而 `@` 跑到了 `Shift + '` 的位置）。



## 选择安装类型

**选择安装类型界面**

选择要安装哪个版本的 Ubuntu Server，以及是否需要附加驱动。

![image-20251029184756732](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029184756732.png)

**`(X) Ubuntu Server`** (Ubuntu 服务器 - 默认)

这是**当前选中的**（用 `(X)` 标记）标准安装选项。它包含了“一套精选的软件包”，为操作服务器提供“舒适的体验”。



**`( ) Ubuntu Server (minimized)`** (Ubuntu 服务器 - 最小化)

这个版本经过定制，运行时占用空间非常小（small runtime footprint），适用于“不期望人类（管理员）登录”的环境。

**注：该版本缺少 `vi`、`nano`、`ping` 等基础命令，但可以通过 apt 安装。**



**附加选项**

**`[ ] Search for third-party drivers`** (搜索第三方驱动程序)

这是一个**未选中**的复选框。如果选中此项，安装程序会搜索并安装“第三方”或“专有”（proprietary）的驱动程序（例如某些特殊的网卡或显卡驱动）。它还警告说，这些驱动有自己的许可证条款，并且不应安装在需要FIPS（一种安全标准）或实时内核的系统上。



## 网络配置

**网络配置（Network configuration）界面**

安装程序默认将网卡配置为 Automatic (DHCP) 模式，在此模式下，系统会通过 DHCP 服务器自动获取 IP 地址。同时，用户也可以选择手动配置网卡的 IPv4 或 IPv6 地址，或者完全禁用该网卡。

如果您配置了网关（无论是通过 DHCP 自动获取还是手动设置），安装程序会默认尝试连接到远程软件源服务器，以下载最新的软件包。如果您的网络无法访问外部服务器，或者访问速度很慢，安装程序会反复尝试连接，导致安装过程被卡住，等待时间非常长。

如果您选择手动配置，并且只设置了 IP 地址和 DNS，但没有配置网关，安装程序将不会尝试连接远程服务器。这将使安装过程跳过网络更新步骤，从而非常顺畅地进行。

如果您在安装时选择了“禁用网卡”，或者选择了“Automatic (DHCP)”但网络中并没有 DHCP 服务器（导致无法自动获取 IP），那么在系统安装完成并首次重启时，网络管理器会因为无法激活网络连接而进入等待状态。这个等待过程通常会长达 2 分钟，直到超时后，系统才会继续执行后续的启动步骤，严重拖慢开机速度。



**基于上述情况，为了避免安装缓慢或启动卡顿，最佳配置建议如下**：

**针对虚拟机环境：**建议在安装操作系统之前，**不要为虚拟机添加任何网络接口卡（NIC）**。先在没有网络的情况下完成整个操作系统的安装。待系统成功安装并首次启动后，再为该虚拟机“热添加”或“关机添加”网卡，然后再进入系统内部进行网络配置。

**针对物理机环境：** 在安装步骤中配置网络时，**为所有网卡手动配置静态 IP 地址、子网掩码**和 DNS 服务器。**但最关键的一点是，*此时不要配置网关（Gateway）***。等到操作系统完全安装成功并进入系统后，再去配置网络。



选择 `ens33` 网卡，将其 IPv4 模式从 "Automatic (DHCP)" 更改为 "Manual"。

![image-20251029191000586](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029191000586.png)

![image-20251029191014743](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029191014743.png)



**配置静态 IP**：

- **子网**：`10.0.0.0/31`
- **IP 地址**：`10.0.0.0`

- **DNS 服务器**：`223.5.5.5,223.6.6.6`

**注意**：当需要配置多个 DNS 服务器时，请确保地址之间使用**英文逗号 (`,`)** 进行分隔。

![image-20251029191046583](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029191046583.png)

![image-20251029191203152](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029191203152.png)



## 代理配置

**代理配置**（Proxy configuration）界面

如果这个系统需要通过代理来连接互联网，请在此输入详情。**否则，请留空**。

**Proxy address：（代理地址：）** - 这是让您输入代理服务器地址的文本框。

代理信息应使用 `http://[[用户][:密码]@]主机[:端口]/` 这样的标准格式。

![image-20251029191958125](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029191958125.png)



## 镜像站配置

**Ubuntu 存档镜像配置（Ubuntu archive mirror configuration）界面**

镜像（Mirror）是指一个包含了所有 Ubuntu 软件包（如系统更新、应用程序）的**软件下载服务器**。

如果使用 Ubuntu 的替代镜像（下载服务器），请在 **Mirror address** 输入**镜像站地址**。

如果服务器网络环境处于中国大陆，建议在此处修改为**国内镜像站地址**。

![image-20251029193127206](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029193127206.png)



## 存储配置

**存储指导配置（Guided storage configuration）界面**

这个界面的核心作用是服务器操作系统设置硬盘空间。

![image-20251029193624254](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029193624254.png)

**`(X) Use an entire disk` (使用整块硬盘)**

- 这是一个自动、向导式的选项。它会自动擦除您选择的整块硬盘（这里是 `/dev/sda`，一个 20GB 的磁盘），并为其创建标准的分区。
- **`[X] Set up this disk as an LVM group` (将此磁盘设置为 LVM 组)**
  - 这个选项默认被选中。LVM (Logical Volume Management, 逻辑卷管理) 是一种高级的磁盘管理方式，它允许您更灵活地创建、调整和管理分区（逻辑卷），例如在未来轻松地扩展空间。推荐保持选中。
  - **`[ ] Encrypt the LVM group with LUKS` (使用 LUKS 加密 LVM 组)**
    - 如果您的服务器包含敏感数据，选中此项可以对整个硬盘进行加密。
    - 您需要设置一个**强密码（Passphrase）**，每次服务器启动时都必须输入这个密码才能解锁硬盘。**请务D必牢记这个密码，丢失它将导致数据永久无法访问。**
    - **`[ ] Also create a recovery key` (同时创建恢复密钥)**
      - 这是加密的附加选项，用于创建备份密钥。



**`( ) Custom storage layout` (自定义存储布局)**

- 这是一个手动、高级的选项。选择此项后，您将进入一个新界面，可以手动创建、删除、调整分区的大小和类型（例如，单独创建 `/boot`、`/` (根目录)、`/home`、`/var` 和 `swap` 交换分区等）。



本示例选择为：自定义存储布局

![image-20251029193700714](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029193700714.png)



### 复杂分区布局示例

注意：这是一个非常复杂的分区布局示例，**极其不推荐在生产环境中使用，该示例让你更加了解分区工具。**

选择 /dev/sda 磁盘，在空闲空间（free space）中创建一个 GPT 分区。配置分区大小为 1 GB，格式化为 ext4，挂载到 /boot 路径。

![image-20251029193744782](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029193744782.png)

![image-20251029193756399](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029193756399.png)

![image-20251029193851961](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029193851961.png)



选择 /dev/sda 空闲空间，创建一个 GPT 分区。配置分区大小为 4 GB，不对该分区进行格式化，不挂载到任何路径。

![image-20251029193844311](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029193844311.png)

![image-20251029194052639](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194052639.png)

![image-20251029194059545](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194059545.png)

![image-20251029194109173](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194109173.png)



按照以上步骤，再创建 3 个 4GB 大小的分区（未格式化、未挂载）。一共 4 个 4GB 大小的分区。

![image-20251029194231725](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194231725.png)



创建一个分区。分区大小为剩余所有空间（不填写大小），不对分区进行格式化，不对分区进行挂载。

![image-20251029194426545](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194426545.png)

![image-20251029194437070](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194437070.png)

![image-20251029194449896](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194449896.png)



利用两个分区（分区 3 和分区 4）创建 RAID 0 逻辑磁盘，命名为 `md0-1`。

![image-20251029194751014](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194751014.png)

![image-20251029194648735](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194648735.png)

![image-20251029194821198](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194821198.png)



利用两个分区（分区 3 和分区 4）创建 RAID 0 逻辑磁盘，命名为 `md0-1`。

![image-20251029194814167](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194814167.png)

![image-20251029194727976](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194727976.png)

![image-20251029194848062](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194848062.png)



利用两个逻辑磁盘（磁盘 `md0-1` 和磁盘 `md0-2`）创建 RAID 0 逻辑磁盘，命名为 `md10`。

![image-20251029194922709](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029194922709.png)

![image-20251029195013235](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195013235.png)

![image-20251029195024097](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195024097.png)



利用一个逻辑磁盘（磁盘 `md10`）和一个分区（ `/dev/sda` 磁盘的分区 7）创建一个 lvm 卷组，命名为 `vg-0`。

![image-20251029195130478](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195130478.png)

![image-20251029195141147](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195141147.png)

![image-20251029195149817](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195149817.png)



在逻辑卷组 `vg0` 中创建一个逻辑卷，命名为 `lv-root`，卷大小为剩余所有空间（不填写），格式化为 ext4，挂载到 / 路径。

![image-20251029195330075](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195330075.png)

![image-20251029195342138](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195342138.png)

![image-20251029195358218](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195358218.png)



此时选择 Done 后按 Enter 键即可进入下一步。在弹出的“确认格式化磁盘”中选择“继续（Continue）”。

![image-20251029195436989](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195436989.png)

![image-20251029195443930](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195443930.png)



### 删除复杂分区布局示例

如果想删除某些逻辑磁盘或分区，是无法直接删除的，为了更好的了解此“存储配置”功能的操作方法，以下演示如何一步一步操作，完全删除所有配置。

注意：可以通过 `restart` 按钮一键删除所有分区配置。

![image-20251029195626686](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195626686.png)

![image-20251029195633807](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195633807.png)

![image-20251029195645821](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195645821.png)

![image-20251029195651532](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195651532.png)



删除 lv-root 逻辑卷

![image-20251029195903959](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195903959.png)

![image-20251029195911514](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195911514.png)

![image-20251029195920887](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195920887.png)



删除 vg0 卷组

![image-20251029195934184](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195934184.png)

![image-20251029195940402](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195940402.png)

![image-20251029195950499](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029195950499.png)



删除 `md10` 逻辑磁盘

![image-20251029200013070](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200013070.png)

![image-20251029200020548](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200020548.png)

![image-20251029200039712](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200039712.png)



删除逻辑磁盘 md0-2。

![image-20251029200104401](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200104401.png)

![image-20251029200111881](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200111881.png)

![image-20251029200123079](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200123079.png)



删除逻辑磁盘 md0-2 。

![image-20251029200147494](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200147494.png)

![image-20251029200153037](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200153037.png)

![image-20251029200159486](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200159486.png)



删除分区 7。按照该方法删除分区 3、4、5 和 6。

![image-20251029200238270](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200238270.png)

![image-20251029200242588](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200242588.png)

![image-20251029200251096](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200251096.png)

![image-20251029200310980](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200310980.png)



删除已挂载到 /boot 路径的分区 2。

![image-20251029200344050](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200344050.png)

![image-20251029200349986](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200349986.png)

![image-20251029200358492](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200358492.png)



删除 BIOS grub spacer 分区 1。

![image-20251029200445195](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200445195.png)

![image-20251029200450561](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200450561.png)

![image-20251029200455919](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200455919.png)



### 标准分区布局方案

下面演示一个标准分区的方案。

创建一个分区，分区大小为 1GB，挂载到 /boot 路径，格式化为 ext4。

![image-20251029200558982](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200558982.png)

![image-20251029200549956](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200549956.png)

![image-20251029200618898](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200618898.png)



创建一个分区，分区大小为剩余所有空间，不对分区进行格式化，不挂载分区。

![image-20251029200709040](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200709040.png)

![image-20251029200717466](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200717466.png)

![image-20251029200722114](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200722114.png)

![image-20251029200744307](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200744307.png)



使用 `/dev/sda` 磁盘分区 3 创建一个 lvm 卷组，命名为 vg0。

![image-20251029200837341](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200837341.png)

![image-20251029200844261](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200844261.png)

![image-20251029200850102](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200850102.png)



在 vg0 卷组上创建一个逻辑卷，命名为 lv-root，分配所有剩余空间，格式化为 ext4，挂载到 / 路径。

![image-20251029200942283](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200942283.png)

![image-20251029200957366](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029200957366.png)

![image-20251029201009530](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029201009530.png)

![image-20251029201018124](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029201018124.png)



## 用户信息配置

**用户信息配置（Profile configuration）界面**

这个界面要求您输入新系统的第一个用户的详细信息。这个用户将自动被赋予 `sudo` 权限，使其能够执行管理员任务。

使用键盘依次填写字段。可以使用**箭头键**或 `Tab` 键在不同的输入框之间移动。

确认所有信息（尤其是用户名和密码）无误后，使用**箭头键**或 `Tab` 键将光标移动到屏幕底部的 **`[ Done ]`** 选项。

按**回车键（Enter）**确认。

![image-20251029202257708](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029202257708.png)

![image-20251029203033705](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029203033705.png)

`Your name` (您的名字)。

这是一个描述性的“全名”，主要用于系统信息展示（例如，在某些桌面环境或用户管理工具中）。

**注意：** 这是一个可选的配置。这**不是**您的登录用户名。



`Your servers name` (服务器名称)

这是您服务器的**主机名 (hostname)**。它将是这台机器在网络上的唯一标识。

建议使用小写字母、数字和连字符 (`-`) 的组合，避免使用空格或特殊字符。

注：可以暂时设置为 `localhost`，后续进入系统后在进行配置。



`Pick a username` (选择一个用户名)

这是您**实际用来登录系统**的账户名。

强烈建议使用全小写、简短的英文名称。这是您的主管理账户。



`Choose a password` (选择一个密码)

为您刚刚创建的用户名（例如 `admin`）设置一个**强密码**。



`Confirm your password` (确认密码)	

再次输入您在上面设置的完全相同的密码，以防止输入错误。



## Ubuntu Pro 配置

**升级到 Ubuntu Pro（Upgrade to Ubuntu Pro）界面**

![image-20251029203049540](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029203049540.png)

**`( ) Enable Ubuntu Pro` (启用 Ubuntu Pro)**

- 如果您选择此项，安装程序会尝试连接到互联网，并要求您提供 Ubuntu One 帐户信息或订阅令牌（Token）来激活 Pro 服务。

**`(X) Skip Ubuntu Pro setup for now` (暂时跳过 Ubuntu Pro 设置)**

- 这是**当前默认选中的选项**。
- 选择此项将跳过激活步骤，继续进行标准的 Ubuntu Server 安装。
- **这不会影响您系统的正常安装和使用。**





Ubuntu Pro 是 Ubuntu 母公司 Canonical 提供的一项**可选的**、基于订阅的服务。**它有一个免费套餐，可供个人在最多 5 台机器上使用。**

它主要为企业和专业用户提供更高级别的安全和支持，例如：

- **扩展安全维护 (ESM):** 为标准支持周期之外的旧版软件（包括 Ubuntu Universe 仓库中的数千个包）提供安全补丁。
- **内核实时补丁 (Livepatch):** 可以在不重启服务器的情况下应用关键的内核安全更新。



**推荐操作**

对于绝大多数用户（包括个人使用、测试或稍后再决定是否使用 Pro 的情况），**强烈建议您执行以下操作：**

1. 保持当前的默认选项 **`(X) Skip Ubuntu Pro setup for now`** 不变。
2. 确保屏幕底部的绿色高亮光标停留在 **`[ Continue ]`** 上。
3. 按**回车键（Enter）**继续安装。

在系统完全安装成功、配置好网络之后，可以随时在服务器的命令行终端中运行 `sudo pro attach` 命令来轻松启用 Ubuntu Pro。在安装时跳过这一步是最简单快捷的选择。



## SSH 配置

**SSH 配置（SSH configuration） 界面**

![image-20251029203430019](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029203430019.png)

**`[ ] Install OpenSSH server` (安装 OpenSSH 服务器)**

- 这是最关键的选项。当前它**未被选中**。
- 如果不选中此项，系统安装后将**无法**通过网络进行远程 SSH 登录。您将只能在机器的物理屏幕前操作。

**`[X] Allow password authentication over SSH` (允许通过 SSH 进行密码认证)**

- 这个选项只有在您选中了上面的 "Install OpenSSH server" 后才真正生效。
- 它允许您使用在**上一步（用户信息配置）\**中创建的\**用户名和密码**来登录 SSH。
- 如果取消选中此项，您将**只能**通过下面导入的 SSH 密钥来登录，密码登录会被禁止（这是更安全的方式）。

**`[ Import SSH key ]` (导入 SSH 密钥)**

- 这是一种更高级、更安全的登录方式。
- 您可以从 GitHub、Launchpad 或一个 URL 导入您的**公钥**。
- 使用密钥登录，您在客户端上（例如您的个人电脑）持有**私钥**，服务器上存有**公钥**。登录时通过密钥对进行身份验证，无需输入密码，这可以有效防止密码被暴力破解。

**`AUTHORIZED KEYS: No authorized key` (已授权的密钥：无)**

- 这里会列出您通过 `[ Import SSH key ]` 成功导入的所有公钥。



推荐的安装教程

**步骤一：选中安装选项**

- 使用键盘的**上/下箭头**键，将光标移动到第一项 **`[ ] Install OpenSSH server`** 上。
- 按**空格键（Spacebar）**将其选中。它会变成 **`[X]`**。

**步骤二：选择登录方式**

- **对于初学者或内部网络（推荐）：**
  - 保持 **`[X] Allow password authentication over SSH`** 处于选中状态。
  - 这样，安装完成后，您就可以立即使用您之前设置的用户名和密码通过 SSH 客户端远程登录。
  - 注意：只有在通过 [ Import SSH key ] 后才能取消选中 `[X] Allow password ...`，**建议在创建用户时配置一个强密码**。进入系统后导入 SSH 私钥并关闭密码登录。
- **为了更高的安全性（推荐用于生产环境）：**
  - （可选）移动到 **`[ Import SSH key ]`** 并按回车键。
  - 按照提示输入您的 GitHub 用户名（它会自动抓取您 GitHub 上的公钥）或选择其他方式导入您的公钥。
  - 导入成功后，您可以（可选）返回并取消选中 `[X] Allow password authentication over SSH`，以强制使用更安全的密钥登录。

**步骤三：完成**

- 在您完成选择后（至少已选中 `[X] Install OpenSSH server`），使用**箭头键**将光标移动到屏幕底部的 **`[ Done ]`**。
- 按**回车键（Enter）**继续下一步的安装。



## 等待安装完成并重启

等待安装完成后会出现 [ Reboot Now ] 选项。

![image-20251029204205126](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029204205126.png)



如出现此界面，请**多次按键盘上的回车键（ Enther ）**。

```
[FAILED] Failed unmounting cdrom.mount - /cdrom.
Please remove the installation medium, then press ENTER:
```

![image-20251029204250602](./images/ubuntu%20%E7%B3%BB%E7%BB%9F%E5%AE%89%E8%A3%85.assets/image-20251029204250602.png)