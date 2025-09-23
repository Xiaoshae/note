# qemu-kvm

## kvm

**KVM**（**Kernel-based Virtual Machine**），顾名思义，是一种基于 Linux 内核的虚拟化技术。它最核心的理念是，直接利用现代处理器内置的硬件虚拟化能力（比如 Intel VT-x 或 AMD-V），将一个标准的 Linux 内核直接变成一个 **Type-1 裸金属**虚拟机监控器（Hypervisor）。

它最独特的地方在于，KVM 本身并不是一个独立的程序，而是一个可以加载的 **Linux 内核模块**（`kvm.ko`）。一旦这个模块被加载，Linux 主机就立刻拥有了强大的 Hypervisor 功能。这意味着所有核心的虚拟化任务，比如 CPU 调度和内存管理，都直接由稳定高效的 Linux 内核来完成，这正是 KVM 性能卓越、运行稳定的关键。

不过，KVM 模块本身只负责最核心的 CPU 和内存虚拟化。对于其他硬件设备，比如网卡、硬盘和显卡，它需要借助一个运行在用户空间的程序来协同工作，实现硬件的模拟。在实践中，它最常见的搭档就是 **QEMU**。



## qemu

QEMU 是一个开源的模拟器，它的核心功能是**模拟整个计算机系统**，包括 CPU、内存、I/O 设备等。这使得它能够在一种架构的主机上运行为另一种架构编译的操作系统或程序。例如，您可以在 x86 架构的电脑上，通过 QEMU 模拟一个 ARM 架构的设备，并在上面运行 Android 系统。



当 QEMU 与 **KVM**（内核虚拟机）结合时，它们共同构成一个完整的虚拟化解决方案，通常称为 **QEMU-KVM**。

在这种模式下：

- KVM 负责利用硬件加速来处理核心的 CPU 和内存虚拟化**，以确保高性能。**
- QEMU 则扮演“前端”和“设备模拟器”的角色**，负责模拟虚拟机的 I/O 设备，如网卡、硬盘和显卡。



### qemu 系列工具

**qemu-system-*** 是 QEMU 最核心的组件，是完整的系统模拟器。星号（`*`）代表不同的CPU架构。例如：

- **qemu-system-x86_64**: 用于模拟 x86_64 架构的计算机。
- **qemu-system-aarch64**: 用于模拟 64 位 ARM 架构的设备。
- **qemu-system-riscv64**: 用于模拟 64 位 RISC-V 架构的系统。



在 RHEL 10 上，不再需要根据不同的 CPU 架构选择不同的 `qemu-system-xxx` 命令。所有的虚拟机启动任务都通过这一个命令来完成，并通过参数来指定机器类型。

```
/usr/libexec/qemu-kvm --version
```

***/usr/libexec** 用于存放那些不打算由用户直接执行的二进制文件。*

*它们是其他程序（通常是位于 `/usr/bin` 或 `/usr/sbin` 中的程序）的辅助工具或“后端”服务。*

*`libexec` 就是 "library executables"（库可执行文件）的缩写。*

*Red Hat 期望您通过 `libvirtd` 服务来管理虚拟机，而 `libvirtd` 会在后台为您调用 `/usr/libexec/qemu-kvm`。*



这里有一个红帽 Bugzilla 上的相关讨论，描述了将多个 QEMU 二进制文件合并为一个的动机和过程。虽然这是一个技术性很强的链接，但它能作为这项变更的直接证据：

- **Red Hat Bugzilla 2074333 - RFE: single qemu binary for all machine types:** [https://bugzilla.redhat.com/show_bug.cgi?id=2074333](https://www.google.com/search?q=https://bugzilla.redhat.com/show_bug.cgi%3Fid%3D2074333)



**qemu-*** 是一组用户空间模拟器，他与 `qemu-system-*` 不同，他用于在一种 CPU 架构上运行为另一种 CPU 架构编译的单个程序。例如：

- **qemu-aarch64**: 可以在 x86_64 架构的 Linux 系统上，直接运行一个为 aarch64 编译的二进制程序。
- **qemu-riscv64**: 类似地，用于运行 RISC-V 程序。
- 这通常与 binfmt_misc 内核功能结合使用，实现对异构架构程序的透明执行，对于交叉编译和开发非常方便。



**qemu-img** 是一个功能强大的磁盘映像管理工具，几乎是使用 QEMU 时必不可少的工具。

**qemu-nbd** 该工具通过网络块设备（Network Block Device, NBD）协议，将一个磁盘映像文件作为网络块设备暴露给主机系统或其他虚拟机。

**qemu-io** 是一个用于磁盘 I/O 性能测试和调试的命令行工具。它允许你直接向磁盘映像文件发送各种 I/O 命令（如读、写、刷新等）。



## qemu-system

### 概述

**qemu-system** 是 QEMU 项目中用于**系统仿真**（System Emulation）的可执行程序系列。与 **qemu-user**（用户模式仿真，只能运行单个程序）不同，**qemu-system** 的核心功能是模拟一个完整的计算机系统，包括 CPU、内存、芯片组以及各种外围硬件设备（如硬盘、网卡、显卡等）。这使得你可以在这个虚拟的计算机上安装并运行一个完整的、未修改的操作系统（Guest OS）。



当**目标架构与宿主机架构相同时**（例如，在 x86_64 的 Linux 主机上运行 x86_64 的虚拟机），**qemu-system** 可以与 **KVM (Kernel-based Virtual Machine)** 协同工作。

**qemu-system** 可以独立工作在**纯软件仿真（TCG, Tiny Code Generator）**模式下。在这种模式下，QEMU 会逐条翻译目标架构的指令，然后在宿主机 CPU 上执行。这种方式兼容性极强，可以在 x86 电脑上模拟 ARM 系统，但性能较低。



**qemu-system** 并不是一个单一的命令，而是一个命令家族。它的命名遵循一个清晰的模式：

```
qemu-system-<arch>
```

*这里的 `<arch>` 指的是你想要**模拟的目标 CPU 架构**。*



重要提示： 在一些较新的发行版（如 RHEL 10）中，为了简化使用，可能会将多个架构的模拟器整合进一个统一的可执行文件，例如 **/usr/libexec/qemu-kvm**。在这种情况下，它会根据你指定的机器类型（-M 参数）来决定模拟哪种架构。但传统的、分散的 `qemu-system-<arch>` 命令在绝大多数系统中仍然是标准。



**支持的加速器**

| 加速器                                | 主机操作系统                           | 主机架构                                         |
| :------------------------------------ | :------------------------------------- | :----------------------------------------------- |
| KVM                                   | Linux                                  | Arm (仅64位), MIPS, PPC, RISC-V, s390x, x86      |
| Xen                                   | Linux (作为 dom0)                      | Arm, x86                                         |
| Hypervisor Framework (hvf)            | macOS                                  | x86 (仅64位), Arm (仅64位)                       |
| Windows Hypervisor Platform (whpx)    | Windows                                | x86                                              |
| NetBSD Virtual Machine Monitor (nvmm) | NetBSD                                 | x86                                              |
| Tiny Code Generator (tcg)             | Linux, 其他 POSIX 系统, Windows, macOS | Arm, x86, Loongarch64, MIPS, PPC, s390x, Sparc64 |



系统模拟功能提供了种类繁多的设备模型，用以模拟您可能希望添加到虚拟机中的各种硬件组件 。这其中包括了大量专为虚拟化环境优化、以实现高效运行的 VirtIO 设备 。部分设备的模拟任务可以通过 vhost-user（针对 VirtIO）或 QEMU 多进程（Multi-process QEMU）技术，从 QEMU 主进程中卸载出去 。此外，如果平台支持，QEMU 还允许将物理设备直接透传给客户机虚拟机，从而彻底消除设备模拟带来的性能开销 。



QEMU 拥有一个功能完备的块设备层（Block Layer），支持构建复杂的多层级存储拓扑，并支持重定向、网络存储、快照及迁移等高级功能 。其灵活的字符设备（chardev）系统，使得通过标准输入输出（stdio）、文件、Unix 套接字（sockets）及 TCP 网络等多种方式处理来自类字符设备的 IO 成为可能 。



QEMU 提供了一系列强大的管理接口。其中包括基于文本行的人机监控协议（Human Monitor Protocol, HMP），允许您动态地添加或移除设备，并审视系统状态 。而 QEMU 监控协议（QEMU Monitor Protocol, QMP）则是一个定义严谨、版本化的机器可读 API，为其他工具创建、控制和管理虚拟机提供了丰富的接口 。许多高级管理工具，例如通过 libvirt 框架运行的 Virt Manager，正是利用此接口与 QEMU 进行交互的 。



对于主流的加速器，QEMU 还通过其 gdbstub 功能提供了强大的调试支持，允许用户连接 GDB 来调试系统软件镜像 。



### 运行 QEMU

QEMU 提供了功能丰富但又错综复杂的 API，完全掌握它可能颇具挑战性 。虽然在某些架构上，仅需一个磁盘镜像就能启动系统，但这类简化示例往往忽略了许多细节，其默认配置对于现代系统而言或许并非最佳选择 。在非 x86 平台上，由于我们模拟的机器类型更为广泛，其命令行通常需要更明确地定义机器类型和启动行为 。

尽管我们不希望阻止用户直接使用命令行来启动虚拟机，但我们必须强调，已有多个项目致力于提供更为友好的用户体验 。那些基于 libvirt 框架构建的工具，能够利用特性探测功能，为您量身打造适合当前硬件环境的现代化虚拟机镜像 。



即便如此，一个典型的 QEMU 命令行结构可以概括如下 ：

```
$ qemu-system-x86_64 [machine opts] \
                [cpu opts] \
                [accelerator opts] \
                [device opts] \
                [backend opts] \
                [interface opts] \
                [boot opts]
```

```
$ qemu-system-x86_64 [机器选项] \
				[CPU选项] \
				[加速器选项] \
				[设备选项] \
				[后端选项] \
				[接口选项] \
				[启动选项]
```



大部分选项都支持显示帮助信息。例如，运行 

```
$ qemu-system-x86_64 -M help 
```

将会列出该 QEMU 程序所支持的所有机器类型 。



`help` 也可以作为其他选项的参数，例如：

```
$ qemu-system-x86_64 -device scsi-hd,help`
```

将会列出 `scsi-hd` 设备可用的附加参数及其默认值 。



### 选项概览

| Options     | Description                                                  |
| :---------- | :----------------------------------------------------------- |
| Machine     | Define the machine type, amount of memory etc                |
| CPU         | Type and number/topology of vCPUs. Most accelerators offer a host cpu option which simply passes through your host CPU configuration without filtering out any features. |
| Accelerator | This will depend on the hypervisor you run. Note that the default is TCG, which is purely emulated, so you must specify an accelerator type to take advantage of hardware virtualization. |
| Devices     | Additional devices that are not defined by default with the machine type. |
| Backends    | Backends are how QEMU deals with the guest's data, for example how a block device is stored, how network devices see the network or how a serial device is directed to the outside world. |
| Interfaces  | How the system is displayed, how it is managed and controlled or debugged. |
| Boot        | How the system boots, via firmware or direct kernel boot.    |

| 选项                 | 描述                                                         |
| :------------------- | :----------------------------------------------------------- |
| 机器 (Machine)       | 定义机器类型、内存大小等。                                   |
| CPU                  | vCPU 的类型、数量/拓扑结构。大多数加速器提供一个 host cpu 选项，它会直接传递您的主机 CPU 配置，而不会过滤掉任何特性。 |
| 加速器 (Accelerator) | 这将取决于您运行的虚拟机监控器 (hypervisor)。请注意，默认是 TCG，这是纯模拟的，因此您必须指定一个加速器类型来利用硬件虚拟化。 |
| 设备 (Devices)       | 机器类型默认未定义的额外设备。                               |
| 后端 (Backends)      | 后端是 QEMU 处理客户机数据的方式，例如块设备如何存储、网络设备如何看到网络或串行设备如何被导向外部世界。 |
| 接口 (Interfaces)    | 系统如何显示、如何被管理和控制或调试。                       |
| 引导 (Boot)          | 系统如何通过固件或直接内核引导来启动。                       |



### 命令行示例

在下面的例子中，我们首先定义了一台 `virt` 类型的机器，这是一个用于运行 Aarch64 客户机的通用平台 。我们启用了虚拟化功能，以便能在模拟的客户机内部继续使用 KVM 。由于 `virt` 机器自带了 pflash 设备，我们为它们命名，以便稍后可以覆盖其默认设置 。

```
$ qemu-system-aarch64 \
-machine type=virt,virtualization=on,pflash0=rom,pflash1=efivars \
-m 4096
```



接着，我们定义了4个虚拟 CPU，并使用 `max` 选项来赋予它们 QEMU 能够模拟的所有 Arm 架构特性 。我们还启用了一个对模拟环境更友好的 Arm 指针认证算法实现 。尽管 TCG 是 QEMU 的默认加速器，我们在此依然明确指定了它 。

```
-cpu max \
-smp 4 \
-accel tcg
```



由于 `virt` 平台本身不带任何默认的网络或存储设备，我们需要手动定义它们 。我们为这些设备指定了 ID，以便稍后能将它们与后端连接起来 。

```
-device virtio-net-pci,netdev=unet \
-device virtio-scsi-pci \
-device scsi-hd,drive=hd
```



然后，我们将用户模式网络（user-mode networking）连接到我们创建的网络设备上。由于用户模式网络无法从外部直接访问，我们通过端口转发，将主机的 2222 端口映射到客户机的 SSH 端口（22） 。

```
-netdev user,id=unet,hostfwd=tcp::2222-:22
```



我们将客户机可见的块设备连接到宿主机上一个专为该客户机准备的 LVM 逻辑分区 。

```
-blockdev driver=raw,node-name=hd,file.driver=host_device,file.filename=/dev/lvm-disk/debian-bullseye-arm64
```



接下来，我们告知 QEMU 将其监控器（Monitor）与串口输出进行多路复用（我们可以通过特定组合键在两者之间切换） 。由于没有配置默认的图形显示设备，我们禁用了显示功能，因为所有操作都将在终端中完成 。

```
-serial mon:stdio \
-display none
```



最后，我们覆盖了默认的固件设置，以确保 EFI 有持久化存储空间来保存其配置 。该固件将负责寻找磁盘、启动 grub，并最终运行我们的操作系统 。

```
-blockdev node-name=rom,driver=file,filename=$(pwd)/pc-bios/edk2-aarch64-code.fd,read-only=true \
-blockdev node-name=efivars,driver=file,filename=$HOME/images/qemu-arm64-efivars
```



### 机器 (Machine)

机器 (Machine) 定义机器类型、内存大小等。







### CPU

CPU 定义 vCPU 的类型、数量/拓扑结构。大多数加速器提供一个 host cpu 选项，它会直接传递您的主机 CPU 配置，而不会过滤掉任何特性。









## qemu-img

