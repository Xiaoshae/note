# SSH

## ssh

ssh 命令用于通过安全通道登录远程主机或在远程主机上执行命令。

```
ssh [选项] [用户@]主机名 [命令]
```

- `-l login_name`：指定登录远程主机的用户名，而不是使用 **user@hostname** 的格式。如果不指定，默认使用当前本地用户的用户名。
- `-p port`：指定远程主机的 SSH 服务端口（默认端口是 **22**）。
- `-i identity_file`：指定用于公钥认证的私钥文件路径（默认是 `~/.ssh/id_rsa` 等）。**私钥文件的权限必须严格（通常为 600）**，否则 ssh 会拒绝使用。
- `-v`：启用详细模式，输出调试日志。可叠加使用（如 `-vvv`）以提高日志详细程度。
- `-X`：启用 **X11 转发**，允许在远程主机运行图形界面程序并显示在本地。
- `-o option`：允许**直接设置 SSH 客户端的配置选项**。



**示例 1：**

```
ssh -l username example.com
```

此命令用于通过 SSH 连接到 `example.com`，并指定使用 `username` 进行登录。



**示例 2：**

```
ssh -i ~/.ssh/mykey user@example.com
```

此命令通过 SSH 连接到 `example.com`，使用 `user` 登录，并**指定使用位于 `~/.ssh/mykey` 的私钥**进行身份验证。



**示例 3：**

```
ssh -v user@example.com
```

```
ssh -vv user@example.com
```

此命令用于通过 SSH 连接到 `example.com`，以 `user` 身份登录，并**启用详细模式输出**，显示连接过程中的调试信息。



**示例 4：**

```
ssh -o StrictHostKeyChecking=no user@server.example.com
```

此命令用于通过 SSH 连接到 `server.example.com`，以 `user` 身份登录。其中，`-o StrictHostKeyChecking=no` 选项表示**禁用严格的主机密钥检查**，即首次连接时不再提示确认主机密钥。



## ssh-copy-id

`ssh-copy-id` 是一个便捷工具，用于将本地 SSH 公钥自动部署到远程主机的 `~/.ssh/authorized_keys` 文件中，实现免密码 SSH 登录。

```
ssh-copy-id [-i [identity_file]] [user@]machine
```

- `-i [identity_file]`：**指定公钥文件路径**，默认为 `~/.ssh/id_rsa.pub`。

- `[user@]machine`: 表示**远程机器的地址**，可以是 IP 地址或主机名。`user` 是远程机器上的用户名；若省略 `user`，则默认使用本地用户的用户名。
- `-p [port]`: 用于**指定 SSH 的非标准端口**，默认端口为 22。
- `-o [option]`: 允许**传递额外的 SSH 选项**，例如 `-o StrictHostKeyChecking=no`（跳过主机密钥验证）。



脚本会自动处理远程机器上 SSH 相关文件的缺失情况：如果远程机器的 `~/.ssh` 目录或 `~/.ssh/authorized_keys` 文件不存在，**脚本将自动创建它们**。

获取到的公钥会被**追加到远程机器的 `~/.ssh/authorized_keys` 文件中**。同时，为了满足 SSH 服务器的 StrictModes 配置要求，脚本会**自动调整远程机器上 `~/.ssh` 目录和 `~/.ssh/authorized_keys` 文件的权限**，通常设置为 `700` 和 `600`，以移除组和其他用户的写权限。

**关于公钥的获取逻辑**：

- 如果使用 **-i 选项并指定公钥路径**，脚本会读取指定的公钥文件。
- 如果仅使用 **-i 选项但未指定路径**，脚本会读取默认公钥文件（~/.ssh/id_rsa.pub）。
- 如果**未指定 -i 选项**，脚本会先尝试通过 **ssh-add -L** 获取 ssh-agent 中的公钥；如果 ssh-agent 没有可用公钥，则回退到默认公钥文件。



## ssh-keygen

ssh-keygen 是 OpenSSH 提供的一个多功能工具，用于生成、管理和转换 SSH 认证密钥。



### 生成 SSH 密钥对

```
ssh-keygen [-t ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa] [-b bits] [-N password] [-Z cipher] [-a rounds] [-f output_keyfile] [-m format] [-q] [-C comment]
```

`-q`：启用静默模式，**不显示生成进度和提示信息**，适合自动化脚本场景。

`-t type`：**指定密钥类型**，支持以下选项：`ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa`。**推荐使用 ed25519**（安全性更高且性能更好）。

`-b bits`：**设置密钥长度**（单位：比特），适用于 RSA 和 ECDSA 类型。RSA 默认 3072 位；ECDSA 根据曲线自动匹配（256、384 或 521 位）。

`-N password`：**设置私钥加密密码**（passphrase）。强烈建议设置强密码以保护私钥安全。若省略此参数，会交互式提示输入（可留空但不推荐）。

`-Z cipher`：**指定私钥加密算法**。默认使用 **aes256-ctr**（安全可靠）。

`-a rounds`：**调整密钥派生函数（KDF）的迭代轮数**（基于 bcrypt_pbkdf）。增加轮数可提升安全性但会降低解密速度。默认 16 轮，建议值 16-100 之间，根据设备性能调整。

`-f output_keyfile`：**自定义密钥文件保存路径**。未指定时默认生成到 `~/.ssh/id_<type>`（例如 `id_ed25519` 和 `id_ed25519.pub`）。

`-m format`：**指定密钥文件存储格式**。默认采用 OpenSSH 私有格式（兼容性好且安全性高）。



### 修改私钥密码

```
ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase] [-P old_passphrase] [-Z cipher]
```

`-p`：**启用密码修改模式**，仅更新私钥密码，不会生成新密钥。

`-f keyfile`：**指定需要修改的私钥文件路径**。若未提供，默认尝试修改 `~/.ssh/id_<type>`（如 `id_rsa`）。

`-P old_passphrase`：**提供当前私钥的旧密码**。若私钥未加密，可留空。

`-N new_passphrase`：**设置新密码**。若省略，会交互式提示输入（可留空但不推荐）。



### 更改密钥注释

```
ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]
```

`-c`：**启用注释修改模式**，仅更新密钥注释，不影响密钥本身。

`-C comment`：**指定新的注释内容**（通常用于标识密钥用途或所有者）。



## sshd_config

`sshd_config` 是 OpenSSH 服务器的核心配置文件，通常位于 `/etc/ssh/sshd_config`。它用于定义 SSH 服务的行为和安全策略，对服务器的远程访问至关重要。



### Port

此参数用于**指定 SSH 服务监听的端口号**。默认情况下，**SSH 使用 22 端口**。您可以设置多个端口，每条 `Port` 命令定义一个监听端口。

```
Port 2222
Port 22222
```



### ListenAddress

`ListenAddress` 参数用于**指定 SSH 服务器监听的 IP 地址**。

如果未指定，**SSH 会默认监听所有本地地址**（包括 IPv4 的 `0.0.0.0` 和 IPv6 的 `::`）。

```
ListenAddress 192.168.1.10
ListenAddress 192.168.1.10:2222
```

此配置表示 SSH 服务将仅监听 IP 地址 `192.168.1.10` 的默认 SSH 端口（22）和 2222 端口。



### PermitRootLogin

此参数**控制是否允许 `root` 用户通过 SSH 登录**。其默认值为 `prohibit-password`。

```
PermitRootLogin no
```

- **yes**：允许 root 登录。
- **no**：禁止 root 登录。
- **prohibit-password**：允许 `root` 用户使用公钥认证登录，但**禁用密码登录**。
- **forced-commands-only**：仅允许 `root` 用户通过公钥认证执行预设的特定命令。



### PasswordAuthentication

控制是否允许使用密码进行认证。默认值：no。

```
PasswordAuthentication no
```

- **no**：**仅允许公钥认证**，这是更安全的推荐设置。
- **yes**：**允许密码登录**，但建议配合强密码策略以确保安全。



### PubkeyAuthentication

此参数**控制是否允许公钥认证**。其默认值为 `yes`。

```
PubkeyAuthentication yes
```



### AuthorizedKeysFile

此参数用于**指定存储用户公钥的文件路径**。默认值为 `.ssh/authorized_keys .ssh/authorized_keys2`。

```
AuthorizedKeysFile .ssh/authorized_keys
```



### AllowUsers

`AllowUsers` 参数用于**指定允许通过 SSH 登录的用户名或用户模式**。默认情况下，所有用户都被允许登录。

此参数支持 `USER@HOST` 格式，可以限制特定用户从特定的源主机登录。此外，它还支持通配符（例如 `user*`）。

```
AllowUsers alice bob@192.168.1.100
```

此配置将仅允许用户 `alice` 登录，以及用户 `bob` 仅能从 IP 地址为 `192.168.1.100` 的主机登录。



其中，`HOST` 表示 SSH 客户端连接时使用的源地址，可以是以下形式：

- **IP 地址**：如 `192.168.1.100` 或 `2001:db8::1`。
- **CIDR 格式**：如 `192.168.1.0/24`，表示一个 IP 地址段。
- **主机名**：如 `client.example.com`。
- **通配符模式**：如 `*.example.com` 或 `192.168.*.*`，支持 `ssh_config(5)` 中定义的 **PATTERNS**（`*` 和 `?`）。



### DenyUsers

`DenyUsers` 参数用于**指定禁止通过 SSH 登录的用户名或用户模式**。默认情况下，没有用户被明确禁止。

此参数用于明确禁止某些用户登录，同样支持 `USER@HOST` 格式和通配符（如 `user*`）。

注意：`DenyUsers` 的优先级高于 `AllowUsers`。

```
DenyUsers hello@192.168.1.200
```

禁止源 IP 为 192.168.1.200 且用户为 hello 登录。



### AllowGroups

`AllowGroups` 参数用于**指定允许通过 SSH 登录的用户组**。默认情况下，所有组的用户都被允许登录。

此参数仅允许指定组的用户登录，支持组名通配符，但**不支持 `USER@HOST` 格式**。

```
AllowGroups sshusers
```



允许组名以 `dev` 开头的组（如 `developers`, `devops`）的用户登录。

```
AllowGroups dev*
```



### DenyGroups

`DenyGroups` 参数用于**指定禁止通过 SSH 登录的用户组**。默认情况下，没有组被明确禁止。

此参数用于禁止指定组的用户登录，支持组名通配符，但**不支持 `USER@HOST` 格式**。

注意：`DenyGroups` 的优先级高于 `AllowGroups`。

```
DenyGroups guests
```



禁止组名以 `test` 开头的组（如 `testgroup`, `testusers`）的用户登录。

```
DenyGroups test*
```



### UseDNS

`UseDNS` 参数控制 SSH 服务器 (`sshd`) 是否对连接客户端的 IP 地址执行**反向 DNS 解析**，以获取其主机名。解析得到的主机名随后可用于匹配 `AllowUsers` 或 `DenyUsers` 配置中的 `HOST` 部分。



如果将 `UseDNS` 设置为 **`no`**：

SSH 服务器将**不会执行 DNS 解析**，仅使用客户端的 IP 地址进行匹配。在这种情况下，`USER@HOST` 配置中的 `HOST` 部分**必须是 IP 地址或 CIDR 格式**（例如 `192.168.1.100` 或 `192.168.1.0/24`），**主机名（如 `client.example.com`）将无效**。



如果将 `UseDNS` 设置为 **`yes`** SSH 服务器将执行一个完整的验证流程：

1. 服务器首先对客户端的 IP 地址进行**反向 DNS 解析**，以获取对应的主机名。
2. 服务器会将解析得到的主机名与 `AllowUsers` 或 `DenyUsers` 配置中的 `HOST` 部分进行匹配。
3. 如果主机名匹配失败，服务器可能还会尝试直接匹配客户端的原始 IP 地址。
4. 服务器会进行**正向 DNS 校验**，确保解析得到的主机名能够重新解析回相同的原始 IP 地址，**防止 DNS 欺骗攻击**。



### MaxAuthTries

**MaxAuthTries** 参数用于指定每个连接的**最大认证尝试次数**，其默认值为 6。

当认证失败次数达到默认值的一半（即 3 次）时，后续的额外失败尝试都将被记录到日志中。合理限制认证失败次数有助于有效**防止暴力破解攻击**。

```
MaxAuthTries 3
```

限制最多尝试 3 次。



### ClientAliveInterval

**ClientAliveInterval** 参数设置服务器检测客户端活跃性的时间间隔，单位为秒。**默认值是 0**，这意味着服务器默认不发送任何检测消息。

ClientAliveInterval 如果客户端在指定时间内没有任何响应，服务器将发送存活检测消息。

此参数通常与 `ClientAliveCountMax` 配合使用，以在超时后断开连接。

```
ClientAliveInterval 15
```



### ClientAliveCountMax

**ClientAliveCountMax** 参数指定在客户端无响应时，服务器允许的最大存活检测次数。**默认值为 3**。

如果客户端连续未能响应指定的次数，服务器将主动断开连接。

超时时间 = ClientAliveInterval × ClientAliveCountMax。

```
ClientAliveCountMax 3
```



### LogLevel

此参数用于设置**日志记录的详细程度**，其**默认值为 INFO**。

**选项**：QUIET、FATAL、ERROR、INFO、VERBOSE、DEBUG、DEBUG1、DEBUG2、DEBUG3。

**INFO 级别会记录基本的运行信息**，DEBUG 级别（如 DEBUG1、DEBUG2、DEBUG3）则会记录非常详细的调试信息。

**不建议在日常使用中开启 DEBUG 级别**，因为它可能会泄露敏感的隐私信息。

```
LogLevel VERBOSE
```



### 参数优先级与逻辑

SSH 服务器在处理登录请求时，会**依照特定的优先级顺序**检查用户和组的访问权限。其逻辑流程如下：

1. **DenyUsers**：服务器会检查尝试登录的**用户是否匹配 DenyUsers 列表**。如果匹配，该用户将被立即禁止登录。
2. **AllowUsers**：如果用户未被 DenyUsers 阻止，并且服务器配置了 AllowUsers 列表，那么**只有匹配该列表的用户才会被允许登录**。如果未设置 AllowUsers，则继续进行下一步检查。
3. **DenyGroups**：在用户通过前述检查后，服务器会进一步检查该用户的**主组或辅助组是否匹配 DenyGroups 列表**。如果匹配，则该用户将被禁止登录。
4. **AllowGroups**：如果用户未被 DenyGroups 阻止，并且服务器配置了 AllowGroups 列表，那么**只有匹配该列表的用户所属组的用户才会被允许登录**。如果未设置 AllowGroups，则默认允许所有用户登录。



## ssh_config

ssh_config 是 OpenSSH 客户端的配置文件，用于自定义 SSH 连接的行为。



配置文件位置

- **用户级别**：`~/.ssh/config`。这是每个用户的个性化配置，其权限应设置为 `600`，即仅用户可读写。
- **系统级别**：`/etc/ssh/ssh_config`。这是全局默认配置，适用于所有用户，通常为只读。



配置格式

- 每行一个参数，格式为 关键字 值。
- 支持 Host 和 Match 块，限制参数适用范围。
- 注释以 # 开头，空行被忽略。



使用 Host * 设置全局默认参数，放在文件末尾。



**Include 指令**：支持包含其他配置文件，便于模块化管理：



### Host

指定配置适用的主机名或模式，支持通配符 `*` 和 `?`。

对于所有 `example.com` 子域的主机，登录时默认使用用户 `alice`。

```
Host *.example.com
    User alice
```



### Hostname

指定实际连接的主机名，可用于别名或 IP 地址。

通过执行 `ssh myserver` 命令，即可连接到 `192.168.1.100`。

```
Host myserver
    Hostname 192.168.1.100
```



### User

指定登录远程主机的用户名。

连接 `server1.example.com` 时，将使用 `bob` 用户进行登录。

```
Host server1
    Hostname server1.example.com
    User bob
```



### Port

指定远程主机的 SSH 端口（默认 22）。

连接 `server2.example.com` 时，将使用 `2222` 端口。

```
Host server2
    Hostname server2.example.com
    Port 2222
```



### IdentityFile

指定用于公钥认证的私钥文件路径。

连接时将使用 `~/.ssh/id_ed25519` 私钥进行认证。

```
Host server3
    Hostname server3.example.com
    IdentityFile ~/.ssh/id_ed25519
```



### StrictHostKeyChecking

控制是否严格检查远程主机密钥，旨在**防止中间人 (MITM) 攻击**。

```
Host *
    StrictHostKeyChecking accept-new
```

- yes：严格检查，不自动添加新密钥。
- accept-new：自动添加新密钥，但拒绝已更改的密钥。
- no：自动接受所有密钥（不安全）。
- ask（默认）：提示用户确认。



### ServerAliveInterval

设置客户端发送心跳消息的间隔（单位：秒），用于检测连接是否存活。通常与 `ServerAliveCountMax` 配合使用。

此配置表示客户端每 60 秒发送一次心跳，如果连续 3 次无响应，则断开连接。

```
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
```



### 示例综合配置

```
# 全局默认设置
Host *
    StrictHostKeyChecking accept-new
    ServerAliveInterval 60
    ServerAliveCountMax 3

# 特定主机配置
Host myserver
    Hostname server.example.com
    User alice
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    LocalForward 8080 localhost:80

# 通过跳板机访问内网
Host bastion
    Hostname bastion.example.com
    User admin

Host internal
    Hostname 10.0.0.100
    ProxyJump bastion
    User bob
```





## 其他配置文件

**~/.ssh/known_hosts**：

- 存储已连接主机的公钥，防止中间人攻击。
- 示例：ssh-keyscan 可更新此文件。



**~/.ssh/authorized_keys**：

- 存储允许登录的公钥，每行一个公钥。
- 权限要求严格：文件权限为 600，目录 ~/.ssh 为 700。



**~/.ssh/id_\***：

- 私钥（如 id_rsa、id_ed25519）和公钥（如 id_rsa.pub）。
- 私钥权限必须为 600。



**/etc/ssh/ssh_host_\*_key**：

- 服务器主机密钥，标识服务器身份。
- 示例：/etc/ssh/ssh_host_ed25519_key。