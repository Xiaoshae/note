# Borg

BorgBackup（简称 Borg）是一款开源备份工具，专为 Unix 类系统（如 Linux）设计。它通过去重（deduplication）、压缩和加密技术，提供高效、安全的备份解决方案。



核心概念：

- **存储库（Repository）**：存储所有备份数据的目录，可位于本地磁盘或远程服务器。
- **归档（Archive）**：存储库中的一个备份快照，记录特定时间点的文件系统状态。
- **去重（Deduplication）**：Borg 将文件分割为可变长度的数据块，仅存储未出现过的块，基于内容定义的哈希值（id_hash，如 HMAC-SHA256）判断重复。
- **加密（Encryption）**：Borg 支持客户端加密，数据在传输到存储库之前加密，确保安全。



## 存储库

存储库是 Borg 备份的基础，必须先初始化。Borg 支持多种加密模式，推荐使用 keyfile（密钥文件存储在文件系统中，受密码保护）。

BorgBackup（简称 Borg）的存储库（Repository）没有显式的“名称”，而是通过其文件系统路径或远程 URL来唯一标识。



### 本地存储库

#### 初始化

创建存储库目录

```
mkdir /backup/borg
```



初始化存储库：

```
borg init --encryption=keyfile /backup/borg
```

初始化时会提示输入密码。选择一个强密码（建议 20 位以上，包含字母、数字和符号），并妥善保存。

**注：加密模式（none、keyfile、repokey 等）在初始化时固定，无法直接从加密转换为未加密，或从一种加密模式切换到另一种。**



#### 参数

**存储库创建的参数**

```
borg init [选项] 存储库路径
```



以下是 borg init 的常用参数，详细说明其作用：

| 参数                           | 描述           | 作用                                                         | 默认值 |
| ------------------------------ | -------------- | ------------------------------------------------------------ | ------ |
| `--encryption=MODE`            | 指定加密模式   | 决定是否加密以及密钥存储方式。支持以下模式：`none`、`keyfile`、`repokey`、 `authenticated`、`keyfile-blake2` / `repokey-blake2`。 | `none` |
| `--append-only`                | 启用仅追加模式 | 限制存储库只能追加数据，防止删除或修改归档。适合远程备份，增强安全性，但需定期清理（`borg compact`）。 | 禁用   |
| `--storage-quota=QUOTA`        | 设置存储配额   | 限制存储库最大大小（如 `10G`、`1T`）。达到配额后，备份失败。 | 无限制 |
| `--make-parent-dirs`           | 自动创建父目录 | 若存储库路径的父目录不存在，自动创建。                       | 禁用   |
| `--lock-wait=SECONDS`          | 锁等待时间     | 设置获取存储库锁的等待时间（秒），避免并发冲突。             | 5 秒   |
| `--repo-only`                  | 仅创建存储库   | 初始化存储库但不创建密钥或密码，适用于特殊场景。             | 禁用   |
| `--additional-free-space=SIZE` | 预留额外空间   | 确保存储库所在文件系统始终有指定可用空间（如 `2G`），防止空间不足。 | 0      |

**none**：数据以明文存储，适合完全信任的存储目标（如本地加密磁盘）。不推荐用于远程备份。

**keyfile**：密钥存储在客户端（~/.config/borg/keys），适合多设备共享存储库的场景。需备份密钥文件。

**repokey**：密钥存储在存储库中，由密码保护。适合单设备或简单管理，推荐初学者使用。

**authenticated**：不加密数据，但使用 HMAC-SHA256 验证完整性，适合对性能要求高但无需加密的场景。

**keyfile-blake2 / repokey-blake2**：与 keyfile/repokey 类似，但使用 BLAKE2b 哈希，性能更优（Borg ≥ 1.1）。

**作用**：加密模式决定数据安全性。加密数据在客户端处理，远程服务器无法访问明文。

**注：加密模式（none、keyfile、repokey 等）在初始化时固定，无法直接从加密转换为未加密，或从一种加密模式切换到另一种。**



存储库初始化后，某些属性可以更改，但核心属性（如加密模式）通常不可直接修改。



#### 更改配置

使用 borg config 修改配额，调整存储库最大大小：

```
borg config /backup/borg storage_quota 20G
```



修改额外空间预留

```
borg config /backup/borg additional_free_space 3G
```



启用或禁用仅追加模式：

```
borg config /backup/borg append_only true
borg config /backup/borg append_only false
```



#### 密钥

keyfile 模式将加密密钥存储在客户端（通常为 ~/.config/borg/keys），而不是存储库中。



查看密钥文件：

```
ls ~/.config/borg/keys
```



备份密钥，为防止丢失，导出密钥到安全位置：

```
borg key export /backup/borg keyfile.backup
```



恢复密钥（若丢失客户端密钥）：

```
borg key import /backup/borg keyfile.backup
```



keyfile 默认由用户在初始化存储库时设置的密码（passphrase）保护。

每次访问存储库（如 borg create、borg extract），需提供密码或通过环境变量设置：

```
export BORG_PASSPHRASE='your_secure_passphrase'
```



更新保护密钥的密码，密钥本身不变。

```
borg key change-passphrase /backup/borg
```





### 远程存储库

若要备份到远程服务器，需在远程服务器上安装 Borg（版本需与客户端一致），远程备份通过 SSH 实现。



生成 SSH 密钥对

```
ssh-keygen -t ed25519
```

按提示保存密钥（默认路径 ~/.ssh/id_ed25519）。



复制公钥到远程服务器：

```
ssh-copy-id user@remotehost
```



初始化远程存储库

```
borg init --encryption=repokey ssh://user@remotehost:/path/to/remote/repo
```

替换 **user** 为远程服务器用户名，**remotehost** 为服务器地址，`/path/to/remote/repo` 为存储库路径。



## 归档

归档是存储库（Repository）中某个时间点的文件系统快照，结合去重（deduplication）技术，仅存储变化的数据块。

归档是 Borg 在存储库中存储的单次备份快照，记录特定时间点的文件和目录状态。每个归档包含文件内容、元数据（如权限、时间戳）和目录结构。

Borg 将文件分割为可变长度的块（chunks），通过 HMAC-SHA256 等哈希值，仅存储未出现过的块。归档之间共享相同的数据块，节省存储空间。



### 创建归档

borg create 是创建归档的核心命令，其基本功能是将指定文件或路径备份到存储库中的一个新归档。以下是命令的基本结构：

```
borg create [选项] REPOSITORY::ARCHIVE_NAME PATH [PATH ...]
```

**REPOSITORY**：存储库路径（如 /backup/borg 或 ssh://user@remotehost:/path/to/repo）。

**ARCHIVE_NAME**：归档的名称，建议包含时间戳（如 backup_2025-06-24）或描述性名称（如 home_backup）。

**PATH**：要备份的文件或目录，可指定多个路径。



备份 /home 目录到本地存储库：

```
borg create /backup/borg::home_backup_2025-06-24 /home
```



备份多个路径（/home 和 /etc）：

```
borg create /backup/borg::full_backup_2025-06-24 /home /etc
```



备份到远程存储库：

```
borg create ssh://user@remotehost:/path/to/repo::home_backup_2025-06-24 /home
```



显示统计信息

```
borg create --stats /backup/borg::home_backup_2025-06-24 /home
```



显示进度

```
borg create --progress /backup/borg::home_backup_2025-06-24 /home
```



排除文件或目录

使用 `--exclude` 或模式文件排除不需要备份的内容：

```
borg create --exclude '/home/*/.cache' --exclude '/var/tmp' /backup/borg::archive_name /home /var
```



使用模式文件： 创建 exclude.txt

```
echo "/home/*/.cache" > exclude.txt
echo "/var/tmp" >> exclude.txt
```

```
borg create --patterns-from exclude.txt /backup/borg::archive_name /home /var
```





### 压缩

Borg 支持多种压缩算法，影响备份速度和存储空间：

| 算法 | 速度         | 压缩率 | 命令示例                  |
| ---- | ------------ | ------ | ------------------------- |
| lz4  | 非常快       | 中等   | --compression lz4         |
| zstd | 可调（1-22） | 高     | --compression zstd,10     |
| zlib | 中等         | 中等   | --compression zlib        |
| lzma | 慢           | 高     | --compression lzma        |
| none | 最快         | 无压缩 | --compression none        |
| auto | 智能选择     | 视算法 | --compression auto,zstd,7 |



示例（使用 zstd 压缩）：

```
borg create --compression zstd,10 /backup/borg::home_backup_2025-06-24 /home
```





### 查看

列出存储库中的归档

```
borg list /backup/borg
```



查看归档中的文件列表

```
borg list /path/to/repo::archive_name
```

- **/path/to/repo**：存储库路径。
- **::archive_name**：要查看的归档名称。



假设存储库位于 /backup/borg，归档名称为 home_backup_2025-06-24：

```
borg list /backup/borg::home_backup_2025-06-24
```

默认会递归列出所有路径（文件和文件夹）



通过管道将 borg list 的输出传递给 grep 和 awk，只列出归档中第一级路径。

```
borg list /backup/borg::home_backup_2025-06-24 | grep -E '^[^/]+/?$' | awk '{print $NF}'
```



### 删除

删除单个归档

```
borg delete /backup/borg::home_backup_2025-06-24
```



删除归档后，运行以下命令压缩存储库，回收空间：

```
borg compact /backup/borg
```



### 恢复

Borg 提供两种恢复方式：提取（extract）和挂载（mount）。



提取整个归档到当前目录：

```
mkdir restore
cd restore
borg extract /backup/borg::home_backup_2025-06-24
```



提取归档中的特定路径（或文件）到当前目录：

```
borg extract /backup/borg::home_backup_2025-06-24 home/user/Documents/file.doc
```

提取单个文件会保留目录结构。



将归档提取为 tar 文件：

```
borg export-tar /backup/borg::home_backup_2025-06-24 /tmp/backup.tar
```



挂载归档

```
mkdir /mnt/borg
borg mount /backup/borg::home_backup_2025-06-24 /mnt/borg
```



卸载：

```
borg umount /mnt/borg
```

