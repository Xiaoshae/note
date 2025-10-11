# PXE

PXE 是由 **Intel** 和 **Systemsoft** 共同制定的一项行业标准，它在设备的**固件**（Firmware）中提供预启动服务。它允许计算机（客户端）在没有操作系统或本地存储设备（如硬盘、U盘）的情况下，仅通过网卡（NIC）从网络服务器上启动。这项由Intel和Systemsoft在1999年发布的技术，已经成为现代数据中心、企业网络和大规模计算机管理的标准工具。

简而言之，它让计算机在操作系统尚未加载时，就能从网络服务器下载启动程序和操作系统镜像。



PXE 的工作流程建立在一套标准的客户端-服务器模型之上，并依赖于几个关键的网络协议，主要是 **DHCP** (动态主机配置协议) 和 **TFTP** (简单文件传输协议)。



## 核心组件

PXE 环境的实现依赖于客户端和服务器端的几个标准网络协议和服务



**PXE 客户端**

需要服务器有一块支持 PXE 的**网卡**（Network Interface Controller, NIC）。几乎所有物理线缆连接的网卡都支持。



**DHCP 服务器**（Dynamic Host Configuration Protocol）

负责给客户端分配 **IP 地址**和其它网络配置参数。

在PXE启动流程中，它还通过特定的DHCP选项向客户端提供引导信息：

- 选项 **DHCP 66 (next-server)** 来指定 **TFTP 服务器的 IP 地址**
- 选项 **DHCP 67 (bootfile-name)** 来指定**网络引导程序 (NBP) 的文件名**。



**TFTP 服务器**（Trivial File Transfer Protocol）：

这是一个轻量级的 FTP 协议，用于在网络中传输启动所需的**初始文件**（如 NBP、内核文件和初始 RAM 磁盘等）。



**HTTP/HTTPS** 服务器

一旦客户端加载了 NBP（iPXE 或其他高级引导加载程序），NBP **下载部署文件（如完整的操作系统镜像、大型安装文件包）时**通常会通过 **HTTP 或 HTTPS** 服务器来传输。

相比于 TFTP，HTTP 传输速度更快，效率更高，更适合传输 GB 级别的大文件。HTTPS 还能提供加密和安全认证。



## 工作流程

### DHCP

**PXE 客户端广播 DHCPDISCOVER 报文**

客户端在本地广播域（Broadcast Domain）内，以广播形式发送一个 `DHCPDISCOVER` 报文。

该报文中的 **选项 60 (Vendor Class Identifier)** 包含了特定于PXE的标识符，例如 `"PXEClient:Arch:xxxxx:UNDI:xxxxxx"`。该选项用于向 DHCP 服务器声明其 PXE 引导意图，以区别于常规的 IP 地址租约请求。



BIOS 客户端和 UEFI 客户端在发送 DHCP 请求包时，会通过一个特定的 **DHCP 选项 93 (Client System Architecture Type)** 来表明自己的“身份”。

**传统BIOS客户端** 发送的DHCP请求中，选项93的值通常是 **`0`** (代表 `Intel x86 PC`)。

**UEFI客户端** 发送的DHCP请求中，选项93的值根据具体架构而不同，例如：

- **`7`** (代表 `x86-64 UEFI`)
- **`9`** (代表 `x86-64 UEFI`)
- **`6`** (代表 `IA-32 UEFI`)

一个配置完善的DHCP服务器会检查这个选项93的值。然后，它会根据这个值，**动态地决定**在选项67（引导文件名）中返回哪一个NBP文件。

BIOS 和 UEFI 是两种完全不同的固件架构，它们无法执行为对方编译的程序。通过这种方式，不同架构的 PXE 客户端可以获取到与之兼容的 NBP 文件。



**DHCP 服务器的引导参数提供**

监听PXE请求的DHCP服务器在接收到 `DHCPDISCOVER` 报文后，会构建一个 `DHCPOFFER` 单播报文作为回应。

`DHCPOFFER` 报文中除了包含IP地址租约信息（`yiaddr` 字段等）外，还必须提供以下PXE专用的引导选项：

- **选项 66 (TFTP Server Name / next-server)**: 指定了提供引导文件的 TFTP 服务器地址。
- **选项 67 (Bootfile Name / filename)**: 定义了需要下载的网络引导程序 (NBP) 的完整路径及文件名。



**DHCP 客户端确认**

客户端接收到一个或多个 `DHCPOFFER` 后，会选择其中一个，并广播一个 `DHCPREQUEST` 报文，此报文的目的在于确认其选择的DHCP服务器及IP地址租约。

被选中的DHCP服务器最终返回一个 `DHCPACK` (DHCP Acknowledgment) 报文，正式确认网络参数分配。

客户端接收到 `DHCPACK` 后，便完成了网络接口的配置，并获得了执行下一步引导所需的全部信息：

- TFTP服务器地址
- NBP文件名



### 下载 NBP 引导程序

PXE客户端通过 DHCP 协议获取到 IP 地址、TFTP服务器地址（由 DHCP 选项 66 指定）以及网络引导程序（NBP）的文件名（由 DHCP 选项 67 定义）。随后，客户端将基于这些信息，使用 TFTP 协议向该服务器发起一个读请求（Read Request, RRQ），用以下载指定的 NBP 文件。



**下载 NBP (网络引导程序) 阶段必须通过 TFTP 协议。**

客户端计算机最初始的引导环境（**网卡上的 PXE 固件** ）。这段固件代码容量非常小（通常只有几十KB），它被烧录在网卡的ROM或主板的固件中。在这个微型环境中，没有空间去实现一个完整的 TCP/IP 协议栈，更不用说复杂的应用层协议如 HTTP 或 FTP 了。

TFTP (Trivial File Transfer Protocol) 协议的设计目标就是“简单”。它基于 UDP，没有复杂的连接状态管理和认证机制，代码实现非常精简，完美契合了固件环境的苛刻要求。



**控制权移交**

下载完成后，NBP (网络引导程序) 的二进制镜像已被完整加载至客户端内存。PXE 固件随即移交系统执行控制权，通过一个跳转指令将 CPU 的执行流重定向至 NBP 镜像的内存入口点 (Entry Point)，从而启动 NBP 的执行流程。



NBP (Network Bootstrap Program) 文件本质上是一个**微型的、专门用于网络引导的加载程序 (Bootloader)**。

它是一个可以直接在计算机的 CPU 上运行的**二进制可执行文件**，CPU 可以直接理解和执行的指令集合。

NBP 文件通常使用非常底层的编程语言编写，主要是 **C 语言**和**汇编语言 (Assembly)**。



**NBP 的核心组件**

1. **网络与文件加载器 (Network & File Loader):** 这是程序的核心。它内置了 TFTP 或更高级的 HTTP/NFS 等网络客户端，负责下载后续所有文件（如配置、内核）。
2. **配置解析器 (Configuration Parser):** 负责读取并理解自身的配置文件（例如 `pxelinux.cfg/default`），根据文件内容决定下一步的具体操作。
3. **用户界面 (User Interface):** 能够在屏幕上绘制一个简单的文本菜单，用于向用户展示可用的启动选项。
4. **执行控制模块 (Execution Control):** 负责将下载的文件放置到正确的内存地址，并在最后将 CPU 控制权精确地移交给操作系统内核。



**NBP 工作流程**

1. **加载配置:** 启动后，首先通过网络下载并解析自身的配置文件，以明确将要执行的任务。
2. **呈现菜单:** (可选) 根据配置在屏幕上显示一个启动菜单，并等待用户做出选择或自动超时。
3. **下载系统组件:** 根据配置指令，通过网络下载操作系统内核 (Kernel) 和初始内存盘 (initrd)。
4. **启动内核:** 将内核和 initrd 放置到正确的内存地址，最后执行跳转指令，将 CPU 的控制权移交给内核，至此 NBP 的任务完成。



## 构建 PXE 环境

操作系统版本（来源于 /etc/os-release 文件和 uname -a 命令，省略部分内容）：

```
root@xiaoshae:~# cat 
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
```

```
Linux xiaoshae 6.8.0-47-generic #47-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 27 21:40:26 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```



网络信息（其他网卡与 PXE 服务无关，不展示）：

```
4: ens38: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:24:d9:8e brd ff:ff:ff:ff:ff:ff
    altname enp2s6
    inet 10.33.1.1/16 brd 10.33.255.255 scope global noprefixroute ens38
       valid_lft forever preferred_lft forever
    inet6 fe80::4447:e0cb:20bb:1db1/64 scope link tentative noprefixroute 
       valid_lft forever preferred_lft forever
```



### tftp 服务器

#### 安装

更新系统软件包列表，安装 tftpd-hpa 软件包，这是一个功能增强的 TFTP 服务器。

```
sudo apt-get update
sudo apt install tftpd-hpa
```



备份配置文件：

```
mv /etc/default/tftpd-hpa /etc/default/tftpd-hpa.back
```



使用文本编辑器 vim 打开配置文件：

```
vim /etc/default/tftpd-hpa
```



将文件内容修改为如下所示。这些设置将使 TFTP 服务器监听所有网络接口的连接，并**允许上传新文件（可选）**。

```
# /etc/default/tftpd-hpa

TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/pxe/tftp"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create --verbose"
```

配置文件参数详解：

​    

**TFTP_USERNAME**: TFTP 服务运行时使用的用户名。

**TFTP_DIRECTORY**: TFTP 的根目录，所有文件都将在此目录下进行传输。

**TFTP_ADDRESS**: 服务器监听的 IP 地址和端口。0.0.0.0:69 表示监听所有 IPv4 地址的 69 端口（TFTP 的标准端口）。

**TFTP_OPTIONS**: 附加选项。

- **--secure**: 将服务器的根目录切换到 TFTP_DIRECTORY 指定的目录，增强安全性。
- **--create**: 允许创建新文件，即允许客户端上传服务器上不存在的文件。



安装 tftpd-hpa 后，如果 /pxe/tftp 目录不存在，则创建该目录。

```
mkdir -p /pxe/tftp
```



为了使 TFTP 服务能够管理该目录下的文件，需要将目录的所有者更改为配置文件中指定的 tftp 用户，并赋予适当的读写执行权限。

```
# 更改目录所有者
sudo chown -R tftp:tftp /pxe/tftp

# 设置目录权限，755 允许所有者读写，其他用户只读
sudo chmod -R 755 /pxe/tftp
```

**注意**：有些教程建议使用 777 权限，这会允许任何用户写入，可能带来安全风险。对于大多数应用场景，755 是一个更安全的选择。



完成配置后，启动（或重启） tftpd-hpa 服务以使更改生效。

```
systemctl start tftpd-hpa
```



**安装 tftpd-hpa 成功后，服务会自动启动。若修改了配置文件，应手动重启 tftpd-hpa 服务，而非再次启动。**

```
systemctl restart tftpd-hpa
```



如果需要服务器在系统重启后自动运行，请启用该服务

```
systemctl enable tftpd-hpa
```

**tftpd-hpa 服务默认为开机自启动。**



#### 简单测试

**安装 TFTP 客户端**

```
apt install tftp-hpa
```



在服务器的 TFTP 根目录中创建一个用于测试下载的文件。

```
echo "tftp test content" | sudo tee /pxe/tftp/test.txt
```



连接到本地 TFTP 服务器并下载文件。

```
# 进入一个可写目录，例如 /tmp
cd /tmp

# 连接并下载文件
tftp localhost
tftp> get test.txt
tftp> quit

# 验证文件是否已下载
cat test.txt
```

注意：TFTP（Trivial File Transfer Protocol，简单文件传输协议）的设计初衷就是极简。它只包含了最**基本的功能：读取文件（GET/下载）和写入文件（PUT/上传）**。该协议本身并未定义列出目录、重命名或删除文件等功能。



创建一个新文件并上传到服务器。

```
echo "upload test" > upload.txt

# 连接并上传文件
tftp localhost
tftp> put upload.txt
tftp> quit

# 在服务器上验证文件是否已上传
ls -l /pxe/tftp/upload.txt
cat /pxe/tftp/upload.txt
```



**注意：测试完成后自行清理测试文件。**



### nginx 服务器

#### 安装

更新软件包列表并安装 nginx 服务。

```
apt-get update
apt -y install nginx
```



Nginx 服务将自动启动。您可以通过以下命令来验证其运行状态：

```
systemctl status nginx
```

**安装成功后会自动启动 Nginx 服务。**



您需要创建一个专门的目录来存放您希望通过 HTTP 提供下载的文件。为了便于管理，我们将其创建在 /srv/http/。

```
mkdir -p /pxe/http/
```



**为 /pxe/http 目录设置正确的所有权和权限**，以确保 Nginx 进程（通常以 www-data 用户身份运行）有权访问这些文件。

```
# 将目录的所有权递归地赋予 www-data 用户和组
sudo chown -R www-data:www-data /pxe/http

# 确保目录及其中的文件具有正确的读取权限
sudo chmod -R 755 /pxe/http
```



为了进行测试，我们可以在这个目录中创建一个示例文件：

```
echo "This is the nginx test file." | tee /pxe/http/nginx_test.txt
```



在 **/etc/nginx/sites-available/** 目录下为您的文件服务器创建一个新的配置文件。

```
vim /etc/nginx/sites-available/file-server
```



将以下内容粘贴到您刚刚创建的 **file-server** 文件中。

```
server {
    listen 80 default_server;

    location / {
        root /pxe/http/;

		# 开启目录浏览功能，当访问一个目录时，会列出其中的文件
        autoindex on;

		# （可选）显示文件的确切大小，而不是以KB、MB、GB为单位
        autoindex_exact_size off;

		# （可选）显示文件的本地时间
        autoindex_localtime on;
		
		charset utf-8;
		
		# 尝试直接提供文件，如果找不到则返回 404 错误
        try_files $uri $uri/ =404;
    }

}
```



以下是无注释版本：

```
server {
    listen 80 default_server;

    location / {
        root /pxe/http/;
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
		charset utf-8;
        try_files $uri $uri/ =404;
    }

}
```



Nginx 通过从 sites-enabled 目录读取配置来加载站点。我们需要创建一个从 sites-available 到 sites-enabled 的符号链接。

```
ln -s /etc/nginx/sites-available/file-server /etc/nginx/sites-enabled/
```



为了避免与默认的 Nginx 欢迎页面冲突，最好移除默认站点的符号链接。

```
rm /etc/nginx/sites-enabled/default
```



在重启服务之前，检查配置文件是否存在语法错误。

```
nginx -t
```



如果您看到如下输出，则表示配置正确：

```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```



**重载 Nginx 服务**，以应用所有更改。

```
systemctl reload nginx
```



**将 Nginx 服务设置为开机自启动。**

```
systemctl enable nginx
```

**nginx 服务默认为开机自启动。**



#### 测试

使用 curl 访问测试是否能正常访问。

```
curl -i http://127.0.0.1/nginx_test.txt
```



以下是 curl 命令的返回内容：

```
curl -i http://127.0.0.1/nginx_test.txt
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Wed, 08 Oct 2025 13:20:22 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 29
Last-Modified: Wed, 08 Oct 2025 13:19:42 GMT
Connection: keep-alive
ETag: "68e664ee-1d"
Accept-Ranges: bytes

This is the nginx test file.
```



**注意：测试完成后自行清理测试文件。**



### kea-dhcp 服务器

#### 安装

更新您的系统软件包列表并安装 Kea DHCPv4 服务器的软件包。

```
apt-get update
apt install kea-dhcp4-server
```



Kea 的配置文件使用 JSON 格式，默认位于 /etc/kea/kea-dhcp4.conf。我们将备份原始文件并创建一个新的配置。



备份默认配置文件

```
mv /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.bak
```



创建并编辑新的配置文件

```
vim /etc/kea/kea-dhcp4.conf
```



将下面的 JSON 配置模板完整地复制并粘贴到文件中。**您需要根据您的网络环境修改其中的占位符**。

```json
{
    "Dhcp4": {
        // 配置 DHCPv4 服务器
        "interfaces-config": {
            // 指定监听的网络接口
            "interfaces": [ "ens38" ]
        },

        // 配置租约存储
        "lease-database": {
            "type": "memfile", // 使用文件存储租约
            "persist": true,   // 持久化存储租约
            "name": "/var/lib/kea/kea-leases4.csv" // 租约文件路径
        },

        // 配置 DHCP 子网
        "subnet4": [
            {
                "subnet": "10.33.0.0/16", // 子网范围
                "pools": [
                    {
                        // 分配的 IP 地址池
                        "pool": "10.33.1.100 - 10.33.1.200"
                    }
                ],

                "next-server": "10.33.1.1", // TFTP 服务器地址
                "boot-file-name": "ipxe.efi", // PXE 启动文件名

                "valid-lifetime": 4000, // 租约有效期（秒）
                "renew-timer": 1000,    // 续租时间（秒）
                "rebind-timer": 2000    // 重新绑定时间（秒）
            }
        ],

        // 配置日志
        "loggers": [
            {
                "name": "kea-dhcp4", // 日志模块名称
                "output_options": [
                    {
                        // 日志文件路径
                        "output": "/var/log/kea/kea-dhcp4.log"
                    }
                ],
                "severity": "INFO", // 日志级别
                "debuglevel": 0     // 调试级别
            }
        ]
    }
}
```



以下是无注释版本：

```json
{
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": [ "ens38" ]
        },

        "lease-database": {
            "type": "memfile",
            "persist": true,
            "name": "/var/lib/kea/kea-leases4.csv"
        },

        "subnet4": [
            {
                "subnet": "10.33.0.0/16",
                "pools": [
                    {
                        "pool": "10.33.1.100 - 10.33.1.200"
                    }
                ],

                "next-server": "10.33.1.1",
                "boot-file-name": "ipxe.efi",

                "valid-lifetime": 4000,
                "renew-timer": 1000,
                "rebind-timer": 2000
            }
        ],

        "loggers": [
            {
                "name": "kea-dhcp4",
                "output_options": [
                    {
                        "output": "/var/log/kea/kea-dhcp4.log"
                    }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}
```



完成配置后，启动 Kea 服务并设置为开机自启。

**启动 kea-dhcp4-server 服务**

```
systemctl start kea-dhcp4-server
```



**安装 kea-dhcp4-server 后，它会自动启动，无需手动启动。如果修改了配置文件，需重启服务以应用更改。**

```
systemctl restart kea-dhcp4-server
```



**验证服务是否正在无错误地运行**

```
systemctl status kea-dhcp4-server
```

如果状态显示为 **active (running)**，则表示服务已成功启动。如果启动失败，通常是配置文件存在语法错误（例如，缺少逗号）或指定的网卡名称不正确。您可以通过 **sudo journalctl -u kea-dhcp4-server -f** 查看实时日志以排查问题。



**设置开机自启**

```
systemctl enable kea-dhcp4-server
```

**kea-dhcp4-server 默认为开机自启动，无需设置。**



### 编译 ipxe

在开始编译之前，您需要一个安装了必要开发工具的 Linux 环境。如果您使用的是基于 Debian/Ubuntu 的发行版，可以运行以下命令安装所需的依赖包：

```
apt-get update
apt install -y git build-essential liblzma-dev
```



从官方仓库克隆 iPXE 的源代码：

```
git clone https://github.com/ipxe/ipxe.git
```



切换到源代码目录

```
cd ipxe/src
```



在 src 目录下，创建一个名为 boot.ipxe 的文件。这个文件将包含您希望 iPXE 在启动时执行的指令。

```
boot.ipxe
```



这是一个 boot.ipxe 文件的示例，您可以根据自己的需求进行修改：

```
#!ipxe

dhcp
```

这里有问题，这只是一个示例。



#### ipxe.efi

**编译为 bin-x86_64-efi 架构的 ipxe.efi 文件**	

使用 make 命令，并指定目标平台为 bin-x86_64-efi/ipxe.efi，同时通过 EMBED 参数嵌入您的 boot.ipxe 脚本。

在 ipxe/src 目录下，运行以下命令：

```
make bin-x86_64-efi/ipxe.efi EMBED=boot.ipxe
```

编译过程可能需要一些时间。成功完成后，您将在 bin-x86_64-efi 目录下找到生成的 ipxe.efi 文件。



#### undionly.kpxe

**编译为 Legacy BIOS 架构的 undionly.kpxe 文件**

```
make bin/undionly.kpxe EMBED=boot.ipxe
```

编译成功后，你可以在 bin 目录下找到生成的 undionly.kpxe 文件
