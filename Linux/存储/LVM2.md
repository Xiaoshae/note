# LVM2

LVM2（Logical Volume Manager 2）是一个功能强大的存储管理工具，它能在 Linux 系统上提供灵活的磁盘空间分配。LVM2 工作的核心思想是抽象化存储设备，将底层的物理硬盘空间组织成逻辑卷，这样你可以更方便地管理文件系统和数据。



## 概念

### 物理卷 PV

物理卷是 LVM 的最底层，代表着实际的物理存储设备，例如硬盘、分区或 RAID 卷。要让 LVM 识别并管理一个设备，必须先将其初始化为一个物理卷，这会写入 LVM 所需的元数据。你可以查看物理卷的信息，例如大小和所属的卷组。当不再需要某个物理卷时，可以在确保其上的数据已被迁移后将其移除。如果底层的物理设备大小发生了变化，可以更新物理卷的大小来匹配。



### 卷组 VG

卷组位于物理卷之上，它将一个或多个物理卷的存储空间汇集在一起，形成一个大的存储池。所有逻辑卷都将从这个存储池中创建。你可以创建卷组，并添加新的物理卷来扩展其容量。要从卷组中移除物理卷，需要先将该物理卷上的数据迁移走。



### 逻辑卷 LV

逻辑卷是 LVM 的最上层，也是用户直接使用的存储单元，它就像一个可以动态调整大小的分区。逻辑卷在卷组的存储池中创建，之后可以在其上创建文件系统并挂载使用。你可以扩展或缩小逻辑卷的大小，也可以创建不同类型的逻辑卷来满足特定的需求，例如：

- **线性卷**：按顺序使用物理卷上的空间。
- **条带卷**：将数据分散存储在多个物理卷上以提高性能。
- **镜像卷**：创建数据副本以提供冗余。
- **精简配置卷**：按需分配存储空间以实现更高的利用率。
- **快照卷**：用于创建逻辑卷在特定时间点的只读副本，非常适合备份。



### PE

**PE (Physical Extent)**，中文常称为“**物理区段**”或“**物理扩展**”，是 LVM 架构中**最小的、连续的存储分配单元**。

当您将一个物理硬盘（如 `/dev/sda1`）添加到 LVM 中（将其初始化为 **PV, Physical Volume**）时，LVM 会在内部将这个 PV 划分为许多大小完全相等的“块”，这些“块”就是 PE。



当使用 `vgcreate` 命令将一个或多个 PV 组合成一个大的“存储池”，即“卷组”。

VG 的总容量就是其包含的所有 PV 中的 PE 数量的总和。**PE 的大小是在创建 VG 时确定的**，并且一旦设定，该 VG 的 PE 大小**不能更改**。





使用 `lvcreate` 命令从 VG 这个“存储池”中划分出一块空间，创建为“逻辑卷”。

当你写入数据时，数据会被存储到哪个物理卷中，不是在写入数据时确定的，而是在创建逻辑卷时就已经确定的。



**PE 的核心作用：映射（Mapping）**

LVM 的所有魔力（如拉伸、缩减、快照、条带化）都源于它维护的一个**映射表**。这个表的核心就是：

**“LV 上的第 N 个 LE 对应到哪个 PV 上的第 M 个 PE”**

- 当您创建一个 LV 时，LVM 就会从 VG 的空闲 PE 池中抓取所需数量的 PE，并将它们“映射”给这个 LV 的 LE。
- 当您扩展 LV 时，LVM 只是从 VG 池中抓取更多的空闲 PE，并将它们添加到这个 LV 的映射表中。



## 语法格式

在 LVM1 的时代，`pvcreate`、`vgcreate`、`lvcreate` 等**确实是各自独立的二进制可执行文件**。它们的功能是分散的。



LVM2 是一个重大的重新设计，它在 LVM1 的基础上提供了更多功能（如快照、集群支持、更灵活的元数据等）。LVM2 大约在 **2002-2003 年**左右开始开发，并随着 Linux 2.6 内核（2003年底发布）的推广而成为标准。

- 所有核心逻辑和功能都被编译进了 `/sbin/lvm` 这一个主程序中，管理员公告 `lvm pvcreate` 等命令进行管理。
- 为了方便使用和保持向后兼容（让习惯了 LVM1 命令的管理员能无缝过渡），LVM2 的安装包在安装时，会创建一系列符号链接（symlinks），如 `pvcreate`、`vgs`、`lvextend` 等，它们全部指向 `/sbin/lvm`。



LVM 的设计思路不是“对象 + 动作”，而**是“动作_对象”（合并为一个词）**。

它是将**操作对象（`lv`, `vg`, `pv`）和动作（`create`, `display`, `remove`）合并成一个单一的子命令**。

LVM2 并没有像 `docker` (`docker container run ...`) 或 `git` (`git branch new ...`) 那样，在 LVM2 时代重新设计一套“名词 + 动词”的现代 CLI 交互方式。它只是把旧的命令“收纳”了进来。



### 基本命令

#### lvmdiskscan

`lvmdiskscan` 是 LVM 的一个基础扫描命令，用于发现系统中所有可供 LVM 使用的块设备。

这是一个**只读**命令。它只进行扫描和报告，不会对您的磁盘或 LVM 元数据进行任何修改，可以安全运行。



当您向系统添加了新硬盘（例如 `/dev/sdb`）或创建了新分区后，运行此命令可以确认 **LVM 是否已经识别到了它们**。

它会明确标识出哪些设备是普通设备（一个 `swap` 分区、`/boot` 分区，或其他文件系统分区），哪些设备**已经**被初始化为 LVM 物理卷 (PV)。



**示例：**

```
# lvm lvmdiskscan 
  /dev/sda2 [       1.00 GiB] 
  /dev/sda3 [   <1023.00 GiB] LVM physical volume
  0 disks
  1 partition
  0 LVM physical volume whole disks
  1 LVM physical volume
```

输出分为两个部分：设备列表和统计摘要。



**设备列表**

```
  /dev/sda2 [       1.00 GiB] 
  /dev/sda3 [    <1023.00 GiB] LVM physical volume
```

**/dev/sda2 [ 1.00 GiB]**：`sda` 硬盘上的第二个分区。LVM 扫描到了这个分区。因为它后面没有 "LVM physical volume" 标记，所以这只是一个普通的设别。LVM 只是在报告已经识别到该设备。

**/dev/sda3 [ <1023.00 GiB] LVM physical volume**：`/dev/sda3`，即 `sda` 硬盘上的第三个分区。**"LVM physical volume"** 信息明确表示 `/dev/sda3` **已经是一个 LVM 物理卷**，它已经被 `pvcreate` 命令初始化过了，并且包含了 LVM 元数据。



**统计摘要**：

**0 disks**：找到了 0 个还不是 LVM PV 的整个磁盘设备。

**1 partition**：找到了 1 个还不是 LVM PV 的分区设备。

**0 LVM physical volume whole disks**：找到了 0 个已经是 LVM PV 的整个磁盘设备。

**1 LVM physical volume**：总共找到了 1 个已经是 LVM PV 的设备。



### PV

PV (物理卷) 命令



#### pvcreate

pvcreate 命令用于将**物理块设备**（如硬盘分区 `/dev/sdb1` 或整个磁盘 `/dev/sdb`）初始化为 LVM **物理卷 (PV)**，使其能够被 LVM 识别并用于后续创建卷组 (VG)。



语法：

```
lvm pvcreate [options] disk1 [disk2 ...]
```



**初始化的一个或多个块设备**：

```
pvcreate /dev/sdb1
```

```
pvcreate /dev/sdb /dev/sdc
```



**[ -f|--force ]**

默认情况下，如果 `pvcreate` 检测到设备上已有文件系统、分区表或其他 LVM 元数据，它会拒绝操作以防数据丢失。使用 `-f` 会**忽略这些警告并强行覆盖**。

这是一个**危险**的选项，请**再三确认**设备上没有重要数据后再使用。如果只是想覆盖 *旧的 LVM* 元数据，使用 `-ff` (两次 force) 会更安全。



**[ -Z|--zero y|n ]**

决定是否**清空**设备开头的第一个扇区（LVM 标签区域）。

- `y` (yes，默认)：清空设备开头的几个扇区，确保清除任何可能存在的旧元数据或签名，这是最安全的做法。
- `n` (no)：不清空。速度稍快，但如果设备上有残留的旧数据，可能会导致 LVM 混淆。



**[ -u|--uuid String ]**

**手动指定**这个物理卷 (PV) 的 UUID (通用唯一标识符)。

默认情况下，LVM 会自动生成一个唯一的 UUID。使用这个选项**手动指定 UUID 的情况非常罕见**，通常只在**灾难恢复**场景中使用（例如，您需要根据元数据备份文件来精确重建一个已损坏的 PV，并且必须保留其原始 UUID）。



#### pvremove

pvremove 命令用于**擦除一个物理卷 (PV) 上的 LVM 标签和元数据**。一旦执行 `pvremove`，LVM 系统将不再把该设备识别为物理卷。它会变回一个普通的块设备。



`pvremove` 是一个具有**破坏性**的命令，但 LVM 提供了安全机制来防止您意外破坏数据。

**您不能**对一个**仍在使用中**（即仍属于某个卷组 VG）的物理卷执行 `pvremove`。如果您尝试这样做，LVM 会拒绝并报错，提示该 PV 仍属于某个 VG。



**擦除一个或多个物理卷设备的 LVM 标签**

```
pvremove /dev/sdb1
```

```
pvremove /dev/sdb1 /dev/sdc1
```



**[ -f|--force ]**

默认情况下，`pvremove` 在擦除标签前会**提示您确认**。如果是使用该选项则会**强制执行，跳过所有交互式确认**。

在自动化脚本中，或者当您非常确定自己的操作时，可用使用该选项。

这**不能**绕过上面提到的“PV 仍在使用中”的安全规则。它只用于跳过确认提示。



#### pvresize

`pvresize` 是一个 LVM 管理命令，其核心功能是**更新 LVM 元数据，使其（LVM）识别的物理卷（PV）大小与底层块设备的实际大小相匹配**。



当**扩大**了底层的磁盘（例如，在 VMware/KVM 中扩展了虚拟磁盘，或者在 AWS/Azure 中扩展了 EBS/Managed Disk），需要：

1. 让操作系统内核识别到新的大小（有时需要重新扫描 SCSI 总线）。
2. 如果 PV 是基于分区的（如 `/dev/sda3`），您可能需要先用 `fdisk`/`parted` 等工具删除该分区并以**新的、更大的**结束扇区重建它（注意：扇区起点必须不变）。
3. 运行 pvresize。



**自动检测新大小并更新 LVM 元数据**

```
pvresize /dev/sda3
```

`pvresize` 会自动检测 `/dev/sda3` 的新大小，并更新 LVM 元数据，将新多出来的空间“添加”到该 PV 中。这些新空间会变成空闲的 PE（Physical Extents），可供您用于 `lvextend` 扩展逻辑卷。



**[ --setphysicalvolumesize ]**

**该参数用于手动指定大小，此模式极其危险**，主要（且几乎是唯一）用于缩减 PV。您是在强制 LVM 认为这个 PV 只有特定大小，即使底层的磁盘实际上更大。

**缩减 PV 的正确流程是：**

1. 使用 `pvmove` 将数据从 PV 的“尾部”移走，确保尾部空间是空闲的。
2. **使用 `pvresize --setphysicalvolumesize`** 将 LVM 中记录的 PV 大小缩减到目标值。
3. （此时 LVM 已经释放了尾部空间）
4. 最后，您才能安全地去缩减底层的分区或 LUN。



#### pvmove

主要功能是在同一个卷组 (VG) 内的物理卷 (PV) 之间进行实时数据迁移。

当 `pvmove` 运行时，它会以“块 (Extent)”为单位，将数据从一个（或多个）源 PV 移动到一个（或多个）目标 PV。这个过程**通常是“在线”的**，意味着您**不需要**卸载文件系统或停止使用该逻辑卷 (LV) 上的应用程序。



**主要使用场景：**

- **替换磁盘**：当一块硬盘（PV）即将发生故障时，您可以使用 pvmove 将其上的所有数据安全地迁移到一块新的、健康的硬盘上，然后再将故障盘从 LVM 中移除。
- **升级磁盘**：将数据从旧的、慢的 HDD 迁移到新的、快的 SSD。
- **腾空 PV**：为了缩减卷组 (VG) 或移除某个 PV（例如 vgreduce），您必须先将其上的所有数据移走。pvmove 就是执行这个“腾空”操作的命令。



**pvmove 的命令格式有两种主要形式**

**将源PV上的所有数据迁移到 VG 中的任何其他可用 PV 上。**

```
pvmove [选项] <源PV>
```



**将源PV上的数据只迁移到指定的 [目标PV] 上。**

    pvmove [选项] <源PV> [目标PV1 目标PV2 ...]



**[ -n|--name LV ]**

默认情况下，`pvmove` 会移动源 PV 上的**所有**数据（属于所有 LV）。使用此参数，您可以指定**只移动**属于特定逻辑卷（如 `my_data_lv`）的数据。



只将属于 `web_data` 这个 LV 且位于 `sdb1` 上的数据移走

```
pvmove -n web_data /dev/sdb1 
```



**[ --atomic ]**

**执行原子操作**。这是 `pvmove` 的关键安全特性。LVM 会创建一个临时的“pvmove 镜像”(通常命名为 `pvmove0`)。数据会先被复制到目标位置，然后 LVM 更新元数据指向新位置，最后删除旧位置的数据。

如果在迁移过程中发生断电或系统崩溃，下次启动时 LVM 会自动恢复或继续迁移，**确保数据不会丢失或损坏**。

**强烈建议始终使用此选项（在很多新版本中可能是默认行为）。**



#### pvs

pvs 以**紧凑的表格形式**显示物理卷的摘要信息，每行一个 PV。



**示例输出：**

```
$ sudo pvs
  PV         VG        Fmt  Attr PSize   PFree 
  /dev/sda2  vg_system lvm2 a--  <19.00g <10.00g
  /dev/sdb1  vg_data   lvm2 a--  <99.00g  12.00g
```



**[ -o|--options String ]**

自定义要显示的列。

例如 `pvs -o pv_name,vg_name,pv_free` 只显示 PV 名称、VG 名称和空闲空间。



**[ -S|--select String ]**

按条件**过滤**结果。

例如 `pvs -S "vg_name = vg_data"` 只显示属于 `vg_data` 卷组的 PV。



**[ -O|--sort String ]**

**排序**结果。

例如 `pvs -O +pv_free` 按空闲空间升序排序，`pvs -O -pv_free` 按降序排序。



#### pvdisplay

`pvdisplay` 提供**最详细**的物理卷信息。默认情况下，它会为每个 PV 显示一个多行的信息块。



**主要用途：**

- 查看某个特定 PV 的**所有**元数据详情。
- 获取 UUID、PE (Physical Extent) 大小、总 PE 数、空闲 PE 数等。
- 查看 PV 上数据块的物理分布（哪个 LV 占用了哪些 PE）。



**示例输出（显示全部）：**

```
$ sudo pvdisplay
  --- Physical volume ---
  PV Name               /dev/sdb1
  VG Name               vg_data
  PV Size               <99.00 GiB / not usable 3.00 MiB
  Allocatable           yes 
  PE Size               4.00 MiB
  Total PE              25343
  Free PE               3072
  Allocated PE          22271
  PV UUID               aBcDeF-GHIj-kLmN-OpQr-StUv-WxYz01
```



**[ PV|Tag ... ]**

可以指定只显示**某一个或多个 PV** 的详细信息 (如 /dev/sdb1)。如果不指定，它会显示所有 PV 的详细信息。

```
pvdisplay /dev/sdb1 /dev/sdb2
```



**[ -m|--maps ]**

**非常有用**的功能。它会显示 PV 上 PE 的**物理分布图**。

可以精确地看到哪个 LV 占用了从第几个 PE 到第几个 PE，以及哪些 PE 是空闲的。

```
# lvm pvdisplay -m 
  --- Physical volume ---
...
   
  --- Physical Segments ---
  Physical extent 0 to 261886:
    Logical volume	/dev/vg0/lv-root
    Logical extents	0 to 261886
```



#### pvscan

`pvscan` 的核心职责**不是显示信息，而是扫描和激活**。

当您插入新硬盘、创建新分区或从 SAN 分配新 LUN 后，LVM 可能不会立即识别到它。运行 `pvscan` (特别是 `pvscan --cache`) 会强制 LVM 重新扫描所有块设备，查找 LVM 标签。

LVM 维护一个元数据缓存 (通常在 `/etc/lvm/cache/.cache`)。`pvscan` 负责更新这个缓存，以便 LVM 命令可以快速运行，而不需要每次都重新扫描所有磁盘。



**pvscan (无参数)**：

运行一次扫描，并显示一个简短的报告，列出找到的 PV 及其所属的 VG。



**pvscan --cache**

扫描所有设备，找到 PV，并**更新 LVM 元数据缓存**。当 LVM 未识别到新磁盘或 PV 时，这通常是您需要运行的命令。



**pvscan --cache -a|--activate ay**

扫描、更新缓存，并**自动激活** (Auto-Activate Yes) 任何现在“完整”的卷组（即该 VG 所需的所有 PV 都已在位）。这是 `udev` 规则在热插拔设备时触发的命令。



### VG

VG (卷组) 命令



#### vgcreate

`vgcreate` 是 LVM (Logical Volume Manager, 逻辑卷管理器) 中用于**创建卷组 (Volume Group)** 的命令。

`vgcreate` 的作用就是初始化一个新的卷组，并将一个或多个已经准备好（已执行 `pvcreate`）的物理卷添加进去。



**基本语法**：

```
vgcreate VG_new PV ...
```

- `VG_new`：你想要创建的新卷组的名称（例如 `my_data_vg`）。
- `PV ...`：一个或多个要添加到此卷组的物理卷的路径（例如 `/dev/sda1` `/dev/sdb1`）。**在执行 `vgcreate` 之前，这些设备必须已经使用 `pvcreate` 命令初始化为物理卷。**



**-s, --physicalextentsize Size[m|UNIT]**

设置该卷组中物理扩展 (Physical Extent, PE) 的大小。

PE 是 LVM 管理磁盘空间的**最小单位**。卷组中的所有空间都被划分为固定大小的 PE 块。逻辑卷的大小必须是 PE 大小的整数倍。

默认大小通常是 4MB。



对于大型磁盘（如 SSD 或 RAID 阵列），使用太小的 PE（如默认的 4MB）会导致元数据(metadata)非常庞大，影响性能。在这种情况下，建议设置更大的 PE，如 `32M` 或 `64M`。

默认情况下，一个 LV 最多只能包含 65536 个 PE。如果你使用默认的 4MB PE，那么单个 LV 的最大尺寸是 `4MB * 65536 = 256GB`。如果你需要一个 1TB 的 LV，你就必须使用更大的 PE（例如，使用 16MB 的 PE，最大 LV 可以达到 `16MB * 65536 = 1TB`）。



**-l, --maxlogicalvolumes Number**

设置这个卷组 (VG) **最多**可以包含多少个逻辑卷 (LV)。

这会影响元数据(metadata)区域的大小。如果你知道你只需要几个 LV，可以把这个值调低以节省元数据空间。



**-p, --maxphysicalvolumes Number**

设置这个卷组 (VG) **最多**可以包含多少个物理卷 (PV)。

这同样会影响元数据(metadata)区域的大小。



**--addtag Tag**

为卷组添加一个“标签”。这在复杂的环境中非常有用，可以用来对存储进行分类（例如，--addtag 'fast_ssd' 或 --addtag 'archive_hdd'）。

后续的命令（如 lvcreate）可以使用这些标签来决定在哪些 PV 上分配空间。



**--alloc contiguous|cling|cling_by_tags|normal|anywhere|inherit**

定义此卷组的默认分配策略，即创建 LV 时 LVM 应如何选择 PE。

- **normal**：默认策略。会尽量避免将同一个 LV 的 PE 分散到不同的 PV 上。
- **contiguous**：要求 LV 的所有 PE 必须是物理上连续的（很少使用，但对某些特定性能场景可能有用）。
- **cling**：将新 LV 的 PE 放置在与现有 LV 相同的 PV 上。
- **anywhere**：LVM 可以在任何地方随意分配 PE，不考虑 PV 分散问题。



#### vgextend

`vgextend` 命令的唯一目的就是**向一个已经存在的卷组 (Volume Group, VG) 中添加一个或多个新的物理卷 (Physical Volume, PV)**。

当你现有的卷组空间不足时，你可以添加一块新硬盘（或分区），将其初始化为物理卷（使用 `pvcreate`），然后使用 `vgextend` 将这个新的物理卷“合并”到现有的卷组中，从而**增加该卷组的总容量**。



**语法格式：**

```
vgextend [选项] <卷组名> <物理卷路径1> [物理卷路径2] ...
```

- **卷组名**： 你想要扩展的目标卷组的名称（例如 `my_vg`）。
- **物理卷路径**： 你想要添加**一个或多个**物理卷的设备路径（例如 `/dev/sdc1`、`/dev/sdd`）。



**将物理卷 /dev/sdd1 添加到 data_vg 卷组中**

```
vgextend data_vg /dev/sdd1
```



**-A | --autobackup y|n**

控制是否在执行命令后**自动备份卷组的元数据**（元数据存储在 `/`etc/lvm/backup/`）。默认为是 (y)，强烈建议保持开启，这是LVM的“后悔药”。



**-f | --force**

**强制**执行。LVM 通常会进行很多安全检查（例如，检查PV是否已被使用）。在 `vgextend` 中，除非LVM提示你某个设备存在问题但你确信可以覆盖，否则不应使用此选项。



**-Z | --zero y|n**

控制是否**清零**新添加的 PV 上的第一个数据扇区。默认为是 (y)，这是一个安全措施，用于擦除该区域可能存在的任何旧的文件系统签名，防止混淆。



**--restoremissing**

这是一个特殊的修复选项。如果某个 PV（硬盘）曾短暂地从卷组中“丢失”（例如，拔掉了又插回去），导致 VG 处于降级状态，当这个 PV 重新出现时，可以使用 `vgextend --restoremissing <VG> <PV>` 来尝试将其“重新添加”回卷组并恢复元数据。



#### vgreduce

vgreduce 的核心功能是从一个卷组 (VG) 中移除一个或多个物理卷 (PV)。

这个操作通常用于缩减卷组大小、替换故障硬盘，或者将物理硬盘从 LVM 管理中释放出来。



**从卷组中移除指定的物理卷**

```
vgreduce [卷组名VG] [物理卷名PV ...]
```

在执行此操作前，**您必须确保要移除的物理卷 (PV) 上没有任何数据（即没有任何 PE 被分配）。**

可以使用 `lvm pvdisplay [PV名]` 来查看 "Allocated PE" 是否为 0。

如果 PV 上有数据，您必须先使用 `pvmove` 命令将数据迁移到卷组中的其他 PV 上。



从 `my_vg` 卷组中移除 `/dev/sdb1` 和 `/dev/sdc1` 这两个物理卷

```
vgreduce my_vg /dev/sdb1 /dev/sdc1 
```



**移除卷组中所有未使用的物理卷**

这是一个便捷选项，用于自动清理卷组中所有完全空闲（未分配任何 PE）的物理卷。

```
vgreduce -a|--all [卷组名VG]
```



扫描 `my_vg`，并移除其中所有未被使用的 PV

```
vgreduce -a|--all [卷组名VG]
```



**移除卷组中丢失的物理卷**

当某个物理卷（如一块硬盘）已经物理损坏、被移除或无法被系统识别时，LVM 会将其标记为 "missing"（丢失）。

卷组可能会工作不正常。`--removemissing` 选项就是用来清理这些丢失的 PV 条目，让卷组恢复到一致状态。

```
vgreduce --removemissing [卷组名VG]
```



从 `data_vg` 中移除所有 LVM 找不到的 PV 记录

```
vgreduce --removemissing [卷组名VG]
```

- 这是一个**修复和清理**操作。
- 如果丢失的 PV 上**没有**逻辑卷数据，此命令会很顺利地清理掉该 PV 的记录。
- 如果丢失的 PV 上**有**数据（即逻辑卷的一部分），LVM 会阻止你操作。此时，你可能需要配合使用 `-f` 或 `--force` 选项，但这**极有可能导致数据丢失**，因为它会强制删除所有部分或全部位于丢失 PV 上的逻辑卷。



**-f | --force**

这是一个**危险**的选项，应谨慎使用。它会跳过一些安全检查。

当与 `--removemissing` 结合使用时，它会**强制删除**那些“不完整”（部分数据在丢失 PV 上）的逻辑卷。**这会导致这些逻辑卷上的数据永久丢失。**

在移除正常的 PV 时，`--force` 很少需要。



**-A | --autobackup y|n**

控制是否在命令执行后自动备份 LVM 元数据。



**--mirrorsonly**

当与 **--removemissing** 结合使用时，它会将操作范围限制为仅移除那些与**镜像（mirror）**逻辑卷相关的丢失 PV。



#### vgremove

vgremove 用于从系统中删除一个或多个卷组。

**删除 VG 会导致该 VG 内的所有 LV（逻辑卷）被移除，**存储在这些 LV 上的**所有数据都将永久丢失**。

在执行此命令前，**必须** 100% 确认你不再需要该 VG 及其包含的所有数据，或者你已经完成了所有必要的数据备份。



默认情况下，`vgremove` 的行为是相对安全的：

- **如果 VG 中仍有 LV 存在：** `vgremove` 会**拒绝删除**，并提示你卷组“仍包含逻辑卷”。
- **如果 VG 为空 (已无 LV)：** `vgremove` 会提示你确认是否要删除这个（空的）卷组。确认后，它会从 LVM 的元数据中移除该 VG 的定义，并释放该 VG 之前占用的所有 PV (Physical Volume, 物理卷)，使这些 PV 可以被用于其他 VG。



**语法：**

```
vgremove VG|Tag|Select ... [ OPTIONS ]
```

- **VG** (最常用): 直接指定卷组的名称。示例: `sudo vgremove data_vg`
- **Tag**: 根据分配给 VG 的 LVM 标签来删除。示例: `sudo vgremove @database_vgs` (删除所有带 `database_vgs` 标签的 VG)
- **Select**: 使用 LVM 的选择标准（一种高级查询语言）来删除。示例: `sudo vgremove -S "vg_size > 1T"` (删除所有大小超过 1TB 的 VG，**极度危险！**)



**-f | --force**

如果 VG 中**仍然包含 LV**，使用 `-f` 会**自动、不经提示**地先执行 `lvremove` 删除所有这些 LV（数据全部丢失！），然后再删除 VG 本身。

即便使用了 `-f`，如果 LV 正处于**打开状态**（例如文件系统已被挂载），`vgremove` 通常也**会失败**，这是一种安全保护机制。你必须先卸载 (unmount) 文件系统。

在处理不完整的、元数据损坏的 VG 时，也可能需要此选项来强制清理。



**--noudevsync**

在 LVM 操作（创建、删除卷）后，它通常会通知 `udev` (Linux 的设备管理器) 来更新 `/dev` 目录下的设备节点（比如 `/dev/vg_name/lv_name`）。使用该选项会**跳过**这个同步步骤。



#### vgrename 

vgrename 用于重命名一个卷组 (Volume Group, VG)。



**按名称重命名**

```
vgrename <旧VG名称> <新VG名称>
```



将名为  **VolGroup00** 的VG重命名为 **vg_system**

```
vgrename VolGroup00 vg_system
```



**按 UUID 重命名**

当您的系统上连接了两个（或更多）同名的 VG 时（例如，克隆硬盘后），您不能使用方式一，因为 LVM 不知道您想重命名哪一个。此时，您必须使用 VG 的 UUID 来唯一标识它。

```
vgrename <VG的UUID> <新VG名称>
```



假设有两个都叫 **data_vg** 的 VG，我们通过 UUID 重命名其中一个

```
vgrename L2xpbS-Tjfw-bVfF-g1fF-T0fM-P1fM-OClcCC vg_clone_data
```



#### vgscan 

`vgscan` 命令用于在系统所有可用的块设备（如硬盘、分区、SAN LUN 等）上扫描 LVM 物理卷 (PV) 元数据，并找出所有存在的卷组 (VG)。



在系统启动过程中，`vgscan` 会被调用（通常由 `systemd-lvm2` 服务触发），以确保所有本地磁盘上的卷组都被识别和激活。

你向服务器添加了新的物理硬盘或分配了新的 LUN，而这些设备上已经存在 LVM 卷组时（例如，从另一台机器迁移过来的），你需要运行 `vgscan` 来让当前系统“发现”这些新来的卷组。



示例：

```
lvm vgscan
```



#### vgs

vgs 命令以**高度可定制的、简洁的表格（摘要）**形式显示卷组的信息。默认情况下，它会为系统上的每个卷组显示一行。



示例：

```
lvm vgs
```

```
# vgs
  VG        #PV #LV #SN Attr   VSize   VFree
  ubuntu-vg   1   2   0 wz--n- <10.00g 4.00m
  data-vg     2   3   0 wz--n-  50.00g 10.00g
```



**-o | --options String** 

**最强大的选项**。允许你自定义输出列。例如，`vgs -o vg_name,vg_size,vg_free,lv_count` 只显示卷组名、总大小、剩余空间和 LV 数量。



#### vgdisplay

vgdisplay 命令以**详细的、多行的键值对**格式显示卷组的所有属性。与 vgs 不同，它的输出非常详尽（Verbose）。



**示例**

```
lvm vgdisplay
```

```
# lvm vgdisplay 
  --- Volume group ---
  VG Name               ubuntu-vg
  System ID
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  3
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                2
  Open LV               2
  MAX PV                0
  Cur PV                1
  Act PV                1
  VG Size               <10.00 GiB
  PE Size               4.00 MiB
  Total PE              2559
  Alloc PE / Size       2558 / 9.99 GiB
  Free  PE / Size       1 / 4.00 MiB
  VG UUID               aBcDeF-1234-XyZ-5678-....
```



**显示单个 vg 的详细信息**

```
lv vgdisplay <vg_name>
```



### LV

LV (逻辑卷) 操作命令。



#### lvcreate

lvcreate 命名用于从一个已经存在的**卷组 (Volume Group, VG)** 中划分出指定大小和类型的空间来创建逻辑卷。



**基本参数**

**-n 或 --name LogicalVolumeName**：为新逻辑卷指定一个**名称**。这个名称在卷组内必须是唯一的。

**-L 或 --size Size[m|UNIT]**：指定逻辑卷的**大小**。单位可以是 K (KB), M (MB), G (GB), T (TB) 等。如 `-L 10G` 。、

**-l 或 --extents Number[PERCENT]**：指定逻辑卷的**大小**（以 "PE" 或 "百分比" 为单位）。如 `-l 100%FREE`，使用当前卷组中**所有剩余的可用空间**。

**VolumeGroup (VG)**：指定要从哪个卷组中创建此 LV。这通常是命令的最后一个参数。



**-l 支持的所有格式**



**绝对 PE 数量** 

**语法:** `-l <Number>`

**示例:** `lvcreate -l 1280 -n lv_data vg_main`



从 `vg_main` 卷组中，分配 **1280 个 PE** 来创建一个名为 `lv_data` 的逻辑卷。

如果 PE Size 是 4MB，这个 LV 的实际大小将是 1280 × 4MB = 5120MB = 5GB。



**可用空间百分比 (%FREE)**

**最常用**的百分比格式。它基于**当前剩余的 PE** (Free PE) 来计算。

**语法:** `-l <Number>%FREE`



**示例 1 :** `lvcreate -l 100%FREE -n lv_archive vg_main`

使用 `vg_main` 中**所有**剩余的可用空间 (100% of Free PE) 来创建 `lv_archive`。



**示例 2:** `lvcreate -l 50%FREE -n lv_web vg_main`

使用 `vg_main` 中剩余可用空间的一半 (50% of Free PE) 来创建 `lv_web`。



**卷组总大小百分比 (%VG)**

**语法:** `-l <Number>%VG`

**示例:** `lvcreate -l 25%VG -n lv_apps vg_main`

创建一个 LV，其大小为**整个 VG 总大小的 25%**。



**特定物理卷大小百分比 (%PV)**

**指定的一个或多个 PV (物理卷) 的总 PE** 来计算 LV 的*大小*。

**语法:** `lvcreate -l <Number>%PV -n <LV_Name> <VG_Name> [PV_Path ...]`

**示例:** `lvcreate -l 50%PV -n lv_from_sdb1 vg_main /dev/sdb1`

此命令会计算 `/dev/sdb1` 这个 PV 在 `vg_main` 中总共贡献了多少 PE。然后，它会创建一个*大小*为" `/dev/sdb1` 总 PE 数的 50%"的 LV。

这**定义的是 LV 的大小**，并且 LVM 会*尝试*从 `/dev/sdb1` 上分配这些 PE。如果 `/dev/sdb1` 空间不足，但 VG 的分配策略允许 (e.g., `normal`)，它可能会从 VG 中的其他 PV 分配空间。





**lvcreate 不仅能创建简单的 LV，还能创建具有高级特性（如性能或冗余）的 LV。**



##### 线性卷

这是最简单、最常用的类型。如果你不指定类型，默认就是线性卷。

数据会**依次**写入底层的物理卷 (PV)。当一个 PV 写满后，LVM 会自动开始写入 VG 中的下一个 PV。



示例：

```
lvcreate -L 20G -n lv_web vg_data
```



##### 条带卷

条带卷将数据"条带化"（切片）并**同时**写入多个物理卷 (PV)。

显著**提高读写性能**，因为 I/O 被分散到了多个磁盘上。

**没有冗余**。如果任何一个 PV 损坏，整个 LV 的数据将全部丢失。



**关键参数**

- `-i` 或 `--stripes Number`：指定条带跨越的 **PV 数量**。
- `-I` 或 `--stripesize Size`：指定每个条带"切片"的大小（通常是 4K 到 512K 之间的 2 的幂）。



**创建一个 100G 的条带卷，数据条带化地写入 vg_fast 中的 2 个 PV**

```
lvcreate -L 100G -i 2 -n lv_striped_fast vg_fast
```



##### 镜像卷 (Mirror / RAID 1)

镜像卷会将数据**完全相同地**写入多个 PV，以提供数据冗余。

**高可靠性**。如果一个 PV 损坏，数据可以从其他镜像副本中恢复。

**空间成本高**。`-m 1` 会消耗 2 倍的物理空间。



**关键参数**：

- `-m` 或 `--mirrors Number`：指定**额外的镜像副本数量**。
- `-m 1` 表示总共有 2 份数据（1 份原始数据 + 1 份镜像）。
- `-m 2` 表示总共有 3 份数据。



**创建一个 50G 的镜像卷，数据会同时写入 2 个不同的 PV（1 个原版 + 1 个镜像）**

```
lvcreate -L 50G -m 1 -n lv_critical_data vg_secure
```



##### 快照卷

快照是 LVM 一个非常强大的功能。它为某个已存在的 "源" LV 创建一个**即时的时间点副本**。



**工作方式** (Copy-on-Write, COW)

当源 LV 上的数据**发生变更**时，LVM 会在**变更发生前**，将**旧的数据块**复制到快照卷中。

快照卷只存储自快照创建以来发生变化的数据块。

你可以对一个繁忙的 LV（如数据库）创建一个快照，然后安全地备份这个“静止”的快照卷，而源 LV 上的服务无需停止。

快照卷的大小必须足够容纳源 LV 在快照生命周期内的所有变更量。如果快照卷空间被写满，快照会失效。



**关键参数**：

- `-s` 或 `--snapshot`：指明这是一个快照卷。
- `OriginLogicalVolume`：要为其创建快照的**源 LV 路径**（例如 `/dev/vg_main/lv_data`）。
- `-L Size`：为快照**分配空间**。



**为 /dev/vg_main/lv_db 创建一个 5GB 大小的快照，名为 lv_db_snap**

```
lvcreate -s -L 5G -n lv_db_snap /dev/vg_main/lv_db
```



##### 精简配置卷

这是现代 LVM 中非常高效的空间管理方式。



**创建精简池 (Thin Pool)**

你首先创建一个 "精简池"，它是一个特殊的 LV，用来容纳一个或多个“精简卷”。



**在 vg_data 中创建一个 100G 的精简池，名为 my_thin_pool**

```
lvcreate -L 100G -n my_thin_pool vg_data --type thin-pool
```

- **--type thin-pool**



**创建精简卷 (Thin Volume)**

精简卷的“虚拟大小”可以**远大于**精简池的实际物理大小（这称为**超售 Over-provisioning**）。

精简卷**只有在实际写入数据时**才会从精简池中分配空间。

极大地提高了空间使用灵活性。你可以创建 10 个 500G 的虚拟磁盘（总共 5TB），而它们共享一个 1TB 的物理精简池。

需要监控精简池的**实际使用率**。如果精简池被写满，所有在池中的精简卷都会冻结（I/O 错误）。



**在 my_thin_pool 中创建一个 500G 的精简卷，名为 thin_lv_01**

```
lvcreate -V 500G -n thin_lv_01 --thinpool my_thin_pool vg_data
```

- `-V` 或 `--virtualsize Size`：指定精简卷的**虚拟大小**。
- `--thinpool PoolName`：指定该卷创建在哪个精简池中。



#### lvextend

lvextend 命令用于**扩展（增加）一个已存在的逻辑卷（Logical Volume, LV）的容量**。



**-L|--size [+]Size[m|UNIT]**

按绝对大小扩展。

`Size` 是一个数字，`UNIT` 是单位 (如 `K`, `M`, `G`, `T`，默认为 `M`)。



**在 lv_data 现有基础上增加 1G**

```
lvextend -L +1G /dev/vg0/lv_data
```



**将 lv_data 的总大小调整到 10G（假设它原来小于10G）**

```
lvextend -L 10G /dev/vg0/lv_data
```



**-l|--extents [+]Number[PERCENT]**

按 LVM 的基本单位 (PE, Physical Extent) 数量扩展。

`+Number`：增加指定数量的 PE。

`Number`：设置总 PE 数量。

`[PERCENT]`：这允许你按百分比扩展，最实用的是 `FREE`。



**使用这个 VG 中所有剩余的空闲空间来扩展 lv_data**

```
lvextend -l +100%FREE /dev/vg0/lv_data
```



**增加 VG 总大小的 50%**

```
lvextend -l +50%VG /dev/vg0/lv_data
```



**-r|--resizefs**

自动调整文件系统。

在 LVM 层面（块设备）扩展逻辑卷后，你**必须**再扩展上层的文件系统（如 ext4, xfs）才能真正使用那些新空间。

如果不带 `-r`，你扩容后还需要手动执行 `resize2fs` (ext4) 或 `xfs_growfs` (xfs) 命令。

**如果带了 `-r`**，`lvextend` 会在扩展 LV 成功后，**自动**帮你调用相应的工具扩展文件系统。



**[PV ...] (在命令末尾指定物理卷)**

默认情况下，`lvextend` 会自动从卷组(VG)中任何有空闲空间的物理卷(PV)上分配空间。

如果你指定了 PV (例如 `/dev/sda2`)，LVM 将**只**尝试从你指定的那个 PV 上获取新空间。



示例：

```
lvextend -L +1G /dev/vg0/lv_data /dev/sda2
```



#### lvreduce

lvreduce 子命令**专门用于缩减一个逻辑卷 (Logical Volume, LV) 的大小**。

这是一个**高风险操作**。在缩减逻辑卷之前，**您必须首先确保逻辑卷之上的文件系统已经被缩减**，并且缩减后的文件系统大小必须**小于或等于**您将要设置的逻辑卷新大小。如果操作不当，**将导致文件系统损坏和数据永久丢失**。



缩减 LV 的操作顺序：

1. **必须**先缩减文件系统。
2. **然后**才能缩减逻辑卷 (LV)。

如果您跳过第一步，或者文件系统缩减后的实际大小依然大于 LV 缩减后的大小，那么位于 LV "尾部" 的文件系统数据将被截断，导致整个文件系统损坏。



lvreduce 的基本语法是：

```
lvreduce [选项] <逻辑卷路径>
```



**将逻辑卷的大小缩减到指定的 10GB**

```
lvreduce -L 10G /dev/vg_main/lv_data
```



**减去指定大小**

```
lvreduce -L -1G /dev/vg_main/lv_data
```

`UNIT`：单位可以是 `k` (KB), `m` (MB), `g` (GB), `t` (TB) 等。



**将逻辑卷缩减到 1280 个 PE**

```
lvreduce -l 1280 /dev/vg_main/lv_data
```



**从当前大小减去 100 个 PE**

```
lvreduce -l -100 /dev/vg_main/lv_data
```



**-r|--resizefs**

**自动调整文件系统**。这是一个非常方便但也需要谨慎使用的选项。

当使用此选项时，`lvreduce` 会**在**缩减 LV **之前**，尝试自动调用相应的文件系统工具（如 `resize2fs`）来缩减文件系统。

这只适用于某些 LVM 知道如何处理的文件系统（如 ext2/3/4）。对于 XFS 等**不支持**在线缩减的文件系统，此选项无效且极其危险。



**-f|--force**

跳过一些交互式确认和安全检查。

它允许您在没有先缩减文件系统的情况下强行缩减 LV，这几乎 100% 会导致数据丢失。**请勿随意使用**。



#### lvresize

lvresize 命令用于**调整（放大或缩小）一个已存在的逻辑卷（Logical Volume, LV）的大小**。通常用于扩展一个快满的磁盘空间，或者在需要时缩减一个分配过大的空间。



**-L, --size [+|-]Size[UNIT]**

按人类可读的单位（如 G, M, T）调整。



将 `data` 卷的大小**设置为 50G**（绝对值）。

```
lvresize -L 50G /dev/vg01/data
```



在 `data` 卷的**当前基础上增加 10G**。

```
lvresize -L +10G /dev/vg01/data
```



在 `data` 卷的**当前基础上缩减 5G**。

```
lvresize -L -5G /dev/vg01/data
```



**-l, --extents [+|-]Number[PERCENT]**

按 LVM 的基本单位“PE”（Physical Extent，物理扩展单元）来调整。



增加 100 个 PE

```
lvresize -l +100 /dev/vg01/data
```



将卷组（VG）中所有剩余的空闲空间都分配给这个 LV

```
lvresize -l +100%FREE /dev/vg01/data
```



**-r, --resizefs**

自动调整文件系统



**-f, --force**

强制执行。



#### lvrename

lvrename 命令用于**更改一个已存在的逻辑卷（LV）的名称**。命令有两种主要的使用格式，效果相同。

​	

**指定卷组 (VG) 和逻辑卷 (LV) 名称**

```
lvrename [VG名] [旧LV名] [新LV名]
```

`[VG名]`：逻辑卷所在的卷组名称。

`[旧LV名]`：你想要重命名的逻辑卷的当前名称。

`[新LV名]`：你希望逻辑卷使用的新名称。



将卷组 "vg01" 中的 "data_lv" 重命名为 "archive_lv"

```
lvrename vg01 data_lv archive_lv
```



**使用逻辑卷的完整路径**

```
lvrename [旧LV的完整路径] [新LV的完整路径]
```

- `[旧LV的完整路径]`：通常是 `/dev/[VG名]/[旧LV名]` 或 `/dev/mapper/[VG名]-[旧LV名]`。
- `[新LV的完整路径]`：通常是 `/dev/[VG名]/[新LV名]`。



**旧 LV 也可以不使用完整路径**，如果你只使用 `LV` 名称（如 `lv_docs`），LVM 会在所有卷组中查找它。如果该名称在系统中不唯一（即多个 VG 中有同名 LV），命令将会失败。



同上，将 /dev/vg01/data_lv 重命名为 /dev/vg01/archive_lv

```
lvrename /dev/vg01/data_lv /dev/vg01/archive_lv
```



**重要注意事项**

重命名逻辑卷 (LV) 本身只是第一步。为了让系统完全识别这个新名称（尤其是挂载的文件系统），你**必须**执行以下后续步骤：

1. **更新 `/etc/fstab` 文件**

   - `lvrename` **不会**自动更新你的 `/etc/fstab` 文件。
   - 如果你的 `/etc/fstab` 中使用设备路径（如 `/dev/vg01/data_lv`）来挂载文件系统，你必须手动将其修改为新路径（如 `/dev/vg01/archive_lv`）。
   - **最佳实践**：在 `/etc/fstab` 中使用 **UUID** (通用唯一标识符) 来挂载文件系统。UUID 在重命名后保持不变，这样可以避免在重命名后出现挂载失败。

2. **更新挂载点 (如果 LV 已挂载)**

   - 如果该 LV 当前已被挂载，`df` 等命令可能仍显示旧名称。
   - 你需要先卸载 (unmount) 该文件系统，然后再用新名称重新挂载 (mount) 它，以使更改完全生效。

   ```
   # 假设 /data 是旧 LV 的挂载点
   umount /data
   
   # (此时应已更新 /etc/fstab)
   
   # 重新挂载
   mount /data
   # 或者使用新路径挂载
   # mount /dev/vg01/archive_lv /data
   ```

3. **重命名根 (Root) 卷**

   - **警告**：重命名包含根文件系统 (`/`) 的逻辑卷是一个**高风险**操作，远比重命名普通数据卷复杂。
   - 你必须额外更新 **GRUB 启动加载器**配置，并**重建 `initramfs`** (初始 RAM 文件系统)，否则系统将在下次启动时因找不到根文件系统而**无法启动**。



#### lvremove

**lvremove** 命令用于删除一个或多个逻辑卷 (Logical Volume, LV) 的命令。

这是一个**破坏性操作**，一旦执行，**逻辑卷上的所有数据都将丢失**，并且通常无法恢复。



基本的语法结构是：

```
lvremove [选项] 逻辑卷路径1 [逻辑卷路径2...]
```

你可以通过多种方式指定要删除的逻辑卷：

- **完整路径:** `lvremove /dev/MyVG/MyLV` (最常见、最明确的方式)
- **卷组/逻辑卷:** `lvremove MyVG/MyLV`
- **仅逻辑卷名:** `lvremove MyLV` (如果名称在所有卷组中是唯一的)



**-f | --force**

这是**最重要也最危险**的选项之一。

它会**强制删除**逻辑卷，**不会**向你请求确认（"Are you sure you want to remove..."）。

它还可以用来尝试删除**当前处于活动状态**（open）的逻辑卷，但这**极不推荐**，可能导致系统不稳定或数据损坏。在删除前，应始终确保逻辑卷已**卸载 (unmounted)** 并**停用 (deactivated)**。



#### lvdisplay

lvdisplay 用于显示一个或多个逻辑卷的详细属性和元数据。

`lvdisplay` 默认以**多行的“键值对”格式**显示每个LV的**所有**元数据。如果您不指定LV名称，它会显示所有LV的详细信息。



示例：

```
lvm lvdisplay
```

```
  --- Logical volume ---
  LV Path                /dev/vg0/lv-root
  LV Name                lv-root
  VG Name                vg0
  LV UUID                LJHRny-9fIE-n0Im-h6Jy-RaUi-lck2-vuPjcn
  LV Write Access        read/write
  LV Creation host, time ubuntu-server, 2025-11-03 15:05:38 +0000
  LV Status              available
  # open                 1
  LV Size                <1023.00 GiB
  Current LE             261887
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           252:0
```



#### lvs

lvs 的主要用途是以**可定制的表格（摘要）形式**列出系统上一个或多个逻辑卷的信息。它非常像 `ls` (列出文件) 或 `ps` (列出进程) 命令，用于快速概览。



示例：

```
lvm lvs
```

```
# lvm lvs
  LV      VG  Attr       LSize     Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  lv-root vg0 -wi-ao---- <1023.00g                                                    
```



配合 `-o` (options) 选项，您可以精确指定要显示的列。这在编写脚本时非常有用。

`lvs -o lv_name,lv_size,vg_name` (只显示名称、大小、卷组)



#### lvscan

lvscan 主要用途是**扫描系统上的所有块设备**，找出属于LVM的物理卷（PV），并列出从这些PV中找到的所有逻辑卷（LV）。

`lvscan` 的输出是三者中最简单的。它通常只列出找到的LV的**设备路径**和**状态**（如 `ACTIVE` 或 `inactive`）。



示例：

```
lvm lvscan
```

```
# lvm lvscan 
  ACTIVE            '/dev/vg0/lv-root' [<1023.00 GiB] inherit
```



 当您添加了新磁盘（可能包含LVM信息，例如从另一台机器迁移过来的磁盘）后，运行 `vgscan`（扫描卷组）和 `lvscan` 可以帮助系统识别它们。



## 典型示例

### 物理卷、卷组、逻辑卷管理

#### 添加物理卷

使用 fdisk -l 查看当前硬盘，当前存在的硬盘。

存在 sda 硬盘，分区为 sda1 sda2 sda3。

```
# fdisk -l 
Disk /dev/sda: 1 TiB, 1099511627776 bytes, 2147483648 sectors
Disk model: VMware Virtual S
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 824DCF65-0391-4463-81E8-E7A000B5B927

Device       Start        End    Sectors  Size Type
/dev/sda1     2048       4095       2048    1M BIOS boot
/dev/sda2     4096    2101247    2097152    1G Linux filesystem
/dev/sda3  2101248 2147481599 2145380352 1023G Linux filesystem
```



添加三块硬盘后，再次使用 fdisk -l 查看。

新增了硬盘 sdb sdc sdd。

```
# fdisk -l 
Disk /dev/sda: 1 TiB, 1099511627776 bytes, 2147483648 sectors
Disk model: VMware Virtual S
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 824DCF65-0391-4463-81E8-E7A000B5B927

Device       Start        End    Sectors  Size Type
/dev/sda1     2048       4095       2048    1M BIOS boot
/dev/sda2     4096    2101247    2097152    1G Linux filesystem
/dev/sda3  2101248 2147481599 2145380352 1023G Linux filesystem


Disk /dev/mapper/vg0-lv--root: 1023 GiB, 1098433691648 bytes, 2145378304 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/sdb: 20 GiB, 21474836480 bytes, 41943040 sectors
Disk model: VMware Virtual S
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/sdc: 20 GiB, 21474836480 bytes, 41943040 sectors
Disk model: VMware Virtual S
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```



将 sdb sdc 转为物理卷

```
lvm pvcreate /dev/sdb /dev/sdc
```

```
# lvm pvcreate /dev/sdb /dev/sdc 
  Physical volume "/dev/sdb" successfully created.
  Physical volume "/dev/sdc" successfully created.
```



#### 创建卷组

创建卷组，命名为 vg1，将 /dev/sdb 和 /dev/sdc 物理卷加入卷组

```
lvm vgcreate vg1 /dev/sdb /dev/sdc
```

```
# lvm vgcreate vg1 /dev/sdb /dev/sdc 
  Volume group "vg1" successfully created
```



#### 创建逻辑卷

创建逻辑卷，命名为 vg1-data，卷大小为卷组全部剩余空间。由于卷组还没有被使用，实际上是全部卷组空间。

```
lvm lvcreate -n vg1-data -l 100%FREE vg1
```



#### 格式化逻辑卷并使用

将逻辑卷 vg1-data 格式化为 ext4 文件系统。

```
mkfs.ext4 /dev/vg1/vg1-data
```

```
# mkfs.ext4 /dev/vg1/vg1-data  
mke2fs 1.47.0 (5-Feb-2023)
Creating filesystem with 10483712 4k blocks and 2621440 inodes
Filesystem UUID: 26cdd81d-dcca-46db-87e6-05788ccee383
Superblock backups stored on blocks: 
	32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208, 
	4096000, 7962624

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (65536 blocks): done
Writing superblocks and filesystem accounting information: done
```



创建 /mnt/data 目录，并将逻辑卷挂载到 /mnt/data 路径。

```
mkdir /mnt/data
```

```
mount /dev/vg1/vg1-data /mnt/data
```



#### 扩展卷组

将 /dev/sdd 转为物理卷

```
lvm pvcreate /dev/sdd
```

```
# lvm pvcreate /dev/sdd 
  Physical volume "/dev/sdd" successfully created.
```



将 /dev/sdd 添加到 vg1 卷组中。

```
lvm vgextend vg1 /dev/sdd 
```

```
# lvm vgextend vg1 /dev/sdd 
  Volume group "vg1" successfully extended
```



#### 扩展逻辑卷

将 vg1 卷组剩余的空间分配给 vg1-data 逻辑卷。

```
lvm lvextend -l +100%FREE /dev/vg1/vg1-data
```

```
# lvm lvextend -l +100%FREE /dev/vg1/vg-data 
  Logical volume vg-data not found in volume group vg1.
```



使用 lvresize 命令扩展，与上面的命令等价：

```
lvm lvresize -l +100%FREE /dev/vg1/vg1-data 
```

```
# lvm lvresize -l +100%FREE /dev/vg1/vg1-data 
  Size of logical volume vg1/vg1-data changed from 39.99 GiB (10238 extents) to <59.99 GiB (15357 extents).
  Logical volume vg1/vg1-data successfully resized.
```



#### 扩展 ext4 文件系统

使用 resize2fs 命令扩展 vg1-data 逻辑卷的文件系统。

```
resize2fs /dev/vg1/vg1-data
```

```
# resize2fs /dev/vg1/vg1-data 
resize2fs 1.47.0 (5-Feb-2023)
Filesystem at /dev/vg1/vg1-data is mounted on /mnt/data; on-line resizing required
old_desc_blocks = 5, new_desc_blocks = 8
The filesystem on /dev/vg1/vg1-data is now 15725568 (4k) blocks long.
```



#### 缩小文件系统

缩小文件系统以移除 /dev/sdc 物理卷。



**卸载文件系统**

在进行任何更改之前，您必须先卸载文件系统。假设文件系统挂载在 `/mnt/data`，您可以运行以下命令：

```
umount /mnt/data
```

如果文件系统正在被使用，您可以使用 `lsof` 或 `fuser` 命令来找出占用它的进程并终止它们。



**检查文件系统**

在调整大小之前，强烈建议您检查文件系统的完整性，以防万一。

```
e2fsck -f /dev/vg1/vg1-data
```

这个命令会对 `/dev/vg1/vg1-data` 上的文件系统进行强制检查。



计算要减小的大小，由于要移除 /dev/sdc 物理卷，所以要从卷组中减少 /dev/sdc 物理卷的总 PE 数量和 PE 大小。

查看 /dev/sdc 的总 PE 数。**总 PE 数量为 5119，PE 大小为 4 MiB**

```
lvm pvdisplay /dev/sdc 
```

```
# lvm pvdisplay /dev/sdc 
  --- Physical volume ---
  PV Name               /dev/sdc
  VG Name               vg1
  PV Size               20.00 GiB / not usable 4.00 MiB
  Allocatable           yes (but full)
  PE Size               4.00 MiB
  Total PE              5119
  Free PE               0
  Allocated PE          5119
  PV UUID               n6V9es-Eu3V-xubB-kgg5-UUXN-JXcv-zKni7V
```



应为要减少的**总 PE 数量为 5119，PE 大小为 4 MiB**。所以需要从文件系统中减少 **20476 MiB（5119 * 4）**。

由于 `resize2fs` 不支持相对大小，你必须**手动计算出最终的绝对大小**。

首先计算出 /dev/vg1/vg1-data 逻辑卷的总大小（单位为 MiB），使用 **fdisk -l /dev/vg1/vg1-data** 查看逻辑卷的总大小。

```
fdisk -l /dev/vg1/vg1-data
```

```
# fdisk -l /dev/vg1/vg1-data 
Disk /dev/vg1/vg1-data: 59.99 GiB, 64411926528 bytes, 125804544 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```



逻辑卷总大小为 **125804544 扇区（sectors）**，每个扇区的大小为 **512 bytes（字节）**，总大小为 **64411926528 bytes（字节）** 

将 **bytes（字节） 转为 MiB（兆字节）**的公式为：**n / 1024 / 1024**

逻辑卷总大小为：**61428 MiB**



逻辑卷总大小为 **61428 MiB（64411926528 / 1024 / 1024）**，需要减少 **20476 MiB**，需要将**文件系统**大小调整为 **40952 MiB**。

```
resize2fs -p /dev/vg1/vg1-data 40952M
```

```
# resize2fs -p /dev/vg1/vg1-data 40952M
resize2fs 1.47.0 (5-Feb-2023)
Resizing the filesystem on /dev/vg1/vg1-data to 10483712 (4k) blocks.
Begin pass 3 (max = 480)
Scanning inode table          XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
The filesystem on /dev/vg1/vg1-data is now 10483712 (4k) blocks long
```



将逻辑卷大小减少 **5119 PE（/dev/sdc 总 PE 为 5119）**

```
lvm lvreduce -l -5119 /dev/vg1/vg1-data 
```

```
# lvm lvreduce -l -5119 /dev/vg1/vg1-data 
  WARNING: Reducing active logical volume to 39.99 GiB.
  THIS MAY DESTROY YOUR DATA (filesystem etc.)
Do you really want to reduce vg1/vg1-data? [y/n]: y
  Size of logical volume vg1/vg1-data changed from <59.99 GiB (15357 extents) to 39.99 GiB (10238 extents).
  Logical volume vg1/vg1-data successfully resized.
```



或者使用 lvresize 子命令，与上面的命令等价

```
lvm lvresize -l -5119 /dev/vg1/vg1-data 
```

```
# lvm lvresize -l -5119 /dev/vg1/vg1-data 
  WARNING: Reducing active logical volume to 39.99 GiB.
  THIS MAY DESTROY YOUR DATA (filesystem etc.)
Do you really want to reduce vg1/vg1-data? [y/n]: y
  Size of logical volume vg1/vg1-data changed from <59.99 GiB (15357 extents) to 39.99 GiB (10238 extents).
  Logical volume vg1/vg1-data successfully resized.
```



#### 迁移物理卷数据并从卷组中移除

查看 /dev/sdd 物理卷，已用 PE 为 0 ，所有 PE 为空闲状态。

```
lvm pvdisplay /dev/sdd
  --- Physical volume ---
  PV Name               /dev/sdd
  VG Name               vg1
  PV Size               20.00 GiB / not usable 4.00 MiB
  Allocatable           yes 
  PE Size               4.00 MiB
  Total PE              5119
  Free PE               5119
  Allocated PE          0
  PV UUID               BUYV5o-vEad-ezKp-eBZh-tweX-Weti-xMQXX2
```

由于 /dev/sdd 是最后一个加入卷组的物理卷，所以当减少逻辑卷大小时，会优先将空闲 PE 规划还给 /dev/sdd 物理卷。



现在可用使用 `lvm vgreduce vg1 /dev/sdd` 将 sdd 从卷组中移除。但我们需要移除的是 /dev/sdc 物理卷，此时 /dev/sdc 物理卷的所有 PE 都在使用状态，无法直接移除。

```
lvm pvdisplay /dev/sdc
```

```
# lvm pvdisplay /dev/sdc 
  --- Physical volume ---
  PV Name               /dev/sdc
  VG Name               vg1
  PV Size               20.00 GiB / not usable 4.00 MiB
  Allocatable           yes (but full)
  PE Size               4.00 MiB
  Total PE              5119
  Free PE               0
  Allocated PE          5119
  PV UUID               n6V9es-Eu3V-xubB-kgg5-UUXN-JXcv-zKni7V
```



可用使用 pvmove 命令将 /dev/sdc 的数据（已使用 PE 迁移）到 /dev/sdd 中。

```
lvm pvmove /dev/sdc
```

```
# lvm pvmove /dev/sdc 
  /dev/sdc: Moved: 2.85%
  /dev/sdc: Moved: 100.00%
```

由于 /dev/sdc 物理卷和 /dev/sdd 物理卷总 PE 数一样，且只有 /dev/sdd 中的 PE 有空闲（所有 PE 空闲），所以 pvmove 命令会自动将 /dev/sdc 的数据迁移到 /dev/sdd 中。



也可以在命令中指定，将 /dev/sdc 的数据迁移到 /dev/sdd 中。该命令和上面的命令等价。

```
lvm pvmove /dev/sdc /dev/sdd
```

```
# lvm pvmove /dev/sdc /dev/sdd 
  /dev/sdc: Moved: 1.15%
  /dev/sdc: Moved: 100.00%
```



将 /dev/sdc 物理卷总 vg1 卷组中移除。

```
lvm vgreduce vg1 /dev/sdc
```

```
# lvm vgreduce vg1 /dev/sdc 
  Removed "/dev/sdc" from volume group "vg1"
```



#### 移除物理卷（转为普通硬盘）

```
lvm pvremove /dev/sdc 
```

```
# lvm pvremove /dev/sdc 
  Labels on physical volume "/dev/sdc" successfully wiped.
```



### 缩小 xfs 文件系统的逻辑卷

XFS 文件系统在创建后，**不支持**直接缩小。这是 XFS 文件系统设计的一个特点。

唯一的办法是：首先完整备份数据，然后卸载并删除当前的文件系统，接着使用 `lvreduce` 命令缩小逻辑卷，之后再创建新的 XFS 文件系统，最后将备份的数据恢复到新的文件系统上。这个过程存在数据丢失的风险，操作前务必谨慎。



## 参考

### pvs 支持的字段

以下为 lvm pvs -o help 的输出结果（AI 翻译）：

