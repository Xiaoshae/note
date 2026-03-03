# Kopia

Kopia 并设置 Kopia 以备份/恢复您的数据。温馨提示：

- `snapshot`（快照）是文件/目录的特定时间点备份；每个快照包含您在需要时可以恢复的文件/目录。
- `repository`（存储库）是保存快照的存储位置；Kopia 支持云端/远程、网络和本地存储位置，并且所有存储库均使用您指定的密码进行加密。
- `policy`（策略）是一组告诉 Kopia 如何创建/管理快照的规则；这包括压缩、快照保留以及计划何时自动拍摄快照等功能。



## 基础示例（入门）

### 创建存储库

您需要做的第一件事是创建一个 `repository`（存储库）。

要创建存储库，请使用 `kopia repository create` 的子命令之一，并按照屏幕上的说明进行操作。在创建存储库时，您必须提供一个密码，该密码将用于加密存储库中的所有快照及其内容。Kopia 使用端到端加密，因此您的密码保留在您的计算机中，不会发送到其他任何地方。

**注意：记住您的存储库密码并确保其安全。如果您忘记了密码，绝对没有办法从存储库恢复任何备份文件！仅需要保存主密码，Kopia 工具无需备份主密钥。**



运行以下命令，在本地文件系统中创建存储库：

```
$ kopia repository create filesystem --path /tmp/my-repository
```



### 连接到存储库

创建存储库后要连接到它，或者要连接到现有的存储库，只需使用 `kopia repository connect` 的子命令之一（而不是 `kopia repository create`）。您可以将任意数量的计算机连接到同一个存储库，甚至可以同时连接。

```
$ kopia repository connect filesystem --path /tmp/my-repository
```



### 创建初始快照

我们创建第一个快照。这就像将 `kopia snapshot create` 指向包含您要备份的文件/目录的目录一样简单，但请注意，您首先需要确保已连接到存储库（见上文）。我们将创建 Kopia 本身源代码的快照：

```
$ kopia snapshot create $HOME/Projects/github.com/kopia/kopia
```



完成后，Kopia 会打印快照根的标识符，该标识符以 `k` 开头：

```
uploaded snapshot 9a622e33ab134ef440f76ed755f79c2f
  (root kfe997567fb1cf8a13341e4ca11652f70) in 1m42.044883302s
```



### 增量快照

让我们再次拍摄相同文件/目录的快照。为此，只需重新运行相同的 `kopia snapshot create` 命令：

```
$ kopia snapshot create $HOME/Projects/github.com/kopia/kopia
```



Kopia 将重新扫描文件/目录，并仅上传已更改的文件内容。假设我们没有对文件/目录进行任何更改，快照根将是相同的，因为 Kopia 中的所有对象标识符都是从底层数据的内容派生而来的：

```
uploaded snapshot 8a45c3b079cf5e7b99fb855a3701607a
  (root kfe997567fb1cf8a13341e4ca11652f70) in 563.670362ms
```



请注意，快照创建几乎是瞬间完成的。这是因为 Kopia 几乎不需要将任何文件上传到存储库，除了关于快照本身的一小部分元数据。

Kopia 中的所有快照始终是增量的；快照只会上传存储库中尚未存在的文件/文件内容，这节省了存储空间和上传时间。这甚至适用于移动或重命名的文件。实际上，如果两台计算机具有完全相同的文件，并且两台计算机都备份到同一个 `repository`，该文件仍将仅存储一次。



### 管理快照

我们可以使用 `kopia snapshot list` 查看目录的快照历史记录：

```
$ kopia snapshot list $HOME/Projects/github.com/kopia/kopia
jarek@jareks-mbp:/Users/jarek/Projects/Kopia
  2019-06-22 20:15:51 PDT kb9a8420bf6b8ea280d6637ad1adbd4c5 61.4 MB drwxr-xr-x files:12500 dirs:798 (latest-5)
  + 1 identical snapshots until 2019-06-22 20:15:57 PDT
  2019-06-22 20:21:39 PDT kbb7dd85a55ca79f282b59b57e5f9c479 61.4 MB drwxr-xr-x files:12500 dirs:798 (latest-3)
  2019-06-22 20:21:42 PDT ke2e07d38a8a902ad07eda5d2d0d3025d 61.4 MB drwxr-xr-x files:12500 dirs:798 (latest-2)
  + 1 identical snapshots until 2019-06-22 20:21:44 PDT
```



要比较两个快照的内容，请使用 `kopia diff`：

```
$ kopia diff kb9a8420bf6b8ea280d6637ad1adbd4c5 ke2e07d38a8a902ad07eda5d2d0d3025d
changed ./content/docs/Getting started/_index.md at 2019-06-22 20:21:30.176230323 -0700 PDT (size 5346 -> 6098)
```



我们可以使用 `kopia ls` 列出目录的内容：

```
$ kopia ls -l kb9a8420bf6b8ea280d6637ad1adbd4c5
-rw-r--r--         6148 2019-06-22 19:01:45 PDT aea2fe8e5ed3104806957f48648c957e   .DS_Store
-rw-r--r--           78 2019-05-09 22:33:06 PDT c829f2205d0ba889ebb354464e14c97a   .gitignore
-rw-r--r--         1101 2019-05-09 22:33:06 PDT 5c4da68139ab0a92a56c334988c75e2a   CONTRIBUTING.md
-rw-r--r--        11357 2019-05-09 22:33:06 PDT 28614f260fab7463e3cd9c410a501c3f   LICENSE
-rw-r--r--         1613 2019-06-22 19:01:17 PDT 5c1f9d67a2b1e2d34fc121ba774266b4   Makefile
-rw-r--r--         2286 2019-05-09 22:33:06 PDT 83a5b758d8409550010786e254096606   README.md
drwxr-xr-x        11264 2019-05-09 22:33:06 PDT kc76b1a9ddf378f803f1710df1150ded6  assets/
drwxr-xr-x         6275 2019-06-02 23:08:14 PDT kf3b4b410df41570345dbc2a8043ee29b  cli2md/
-rw-r--r--         3749 2019-05-14 19:00:21 PDT 8c9e27bed2f577b31b07b07da4bdfffb   config.toml
drwxr-xr-x       879721 2019-06-22 20:15:45 PDT k24eb31a05b81d1a83c47c40a4f7b9f0e  content/
-rwxr-xr-x          727 2019-05-09 22:33:06 PDT 2c08f511019f1f5f45f889909c755a9b   deploy.sh
drwxr-xr-x         1838 2019-05-14 19:00:21 PDT k024f1106e0cd56e2c6611cf884a30894  layouts/
drwxr-xr-x     13682567 2019-06-22 18:57:48 PDT k181d6990e75dd783bd50dae36591622a  node_modules/
-rw-r--r--        94056 2019-06-22 18:57:49 PDT ed474fb638d2a3b1c528295d1586466a   package-lock.json
-rw-r--r--          590 2019-05-09 22:33:06 PDT ee85ae1f1cdb70bbd9e335be9762c251   package.json
drwxr-xr-x      7104710 2019-06-22 19:01:38 PDT keb814d92fe795b96795d5bdbfa816ad6  public/
drwxr-xr-x       904965 2019-06-22 20:13:56 PDT k7bf88a7ca076b03f0dafc93ab5fa2263  resources/
drwxr-xr-x     38701570 2019-06-01 20:11:32 PDT kdb9f41fc8db5c45b1aec06df001be995  themes/
```



对于目录中的每个文件/目录，Kopia 存储其名称、大小、属性和具有文件或目录内容的对象 ID。

要检查文件的内容，请使用 `kopia show` 并传递您要检查的文件或目录的对象标识符：

```
$ kopia show 8c9e27bed2f577b31b07b07da4bdfffb
```



目录存储为 JSON 对象，因此可以使用 `kopia content show` 以及目录的对象标识符（`-j` 选项显示格式化后的 JSON），将它们的内容作为常规文件查看：

```
$ kopia content show -j kb9a8420bf6b8ea280d6637ad1adbd4c5
```

此命令返回：

```json
{
  "stream": "kopia:directory",
  "entries": [
    {
      "name": "assets",
      "type": "d",
      "mode": "0755",
      "mtime": "2019-05-14T18:24:15-07:00",
      "uid": 501,
      "gid": 20,
      "obj": "kc76b1a9ddf378f803f1710df1150ded6",
      "summ": {
        "size": 11264,
        "files": 2,
        "dirs": 3,
        "maxTime": "2019-05-09T22:33:06-07:00"
      }
    },
    ...
    {
      "name": "package.json",
      "type": "f",
      "mode": "0644",
      "size": 590,
      "mtime": "2019-05-09T22:33:06-07:00",
      "uid": 501,
      "gid": 20,
      "obj": "ee85ae1f1cdb70bbd9e335be9762c251"
    }
  ],
  "summary": {
    "size": 61414615,
    "files": 12500,
    "dirs": 798,
    "maxTime": "2019-06-22T20:15:45.301289096-07:00"
  }
}
```



### 挂载快照并从快照恢复文件/目录

我们可以使用 `kopia mount` 命令将快照的内容挂载为本地文件系统，并使用常规文件命令检查其内容：

```
$ mkdir /tmp/mnt
$ kopia mount kb9a8420bf6b8ea280d6637ad1adbd4c5 /tmp/mnt &
$ ls -l /tmp/mnt/
total 119992
-rw-r--r--  1 jarek  staff      1101 May  9 22:33 CONTRIBUTING.md
-rw-r--r--  1 jarek  staff     11357 May  9 22:33 LICENSE
-rw-r--r--  1 jarek  staff      1613 Jun 22 19:01 Makefile
-rw-r--r--  1 jarek  staff      2286 May  9 22:33 README.md
drwxr-xr-x  1 jarek  staff     11264 May  9 22:33 assets
drwxr-xr-x  1 jarek  staff      6275 Jun  2 23:08 cli2md
-rw-r--r--  1 jarek  staff      3749 May 14 19:00 config.toml
drwxr-xr-x  1 jarek  staff    879721 Jun 22 20:15 content
-rwxr-xr-x  1 jarek  staff       727 May  9 22:33 deploy.sh
drwxr-xr-x  1 jarek  staff      1838 May 14 19:00 layouts
drwxr-xr-x  1 jarek  staff  13682567 Jun 22 18:57 node_modules
-rw-r--r--  1 jarek  staff     94056 Jun 22 18:57 package-lock.json
-rw-r--r--  1 jarek  staff       590 May  9 22:33 package.json
drwxr-xr-x  1 jarek  staff   7104710 Jun 22 19:01 public
drwxr-xr-x  1 jarek  staff    904965 Jun 22 20:13 resources
drwxr-xr-x  1 jarek  staff  38701570 Jun  1 20:11 themes
$ umount /tmp/mnt
```

挂载目前是推荐的从快照中恢复文件/目录的方法。但是，您也可以使用 `kopia snapshot restore` 命令从快照恢复文件/目录。



### 策略

策略可用于指定如何获取和保留 Kopia 快照。我们可以定义各种不同的 `policy` 选项，包括：

- 要忽略哪些文件
- 保留多少每小时、每天、每周、每月和每年的快照
- 制作快照的频率
- 是否压缩文件



每个 `repository` 都有一个 `global`（全局）策略，如果特定策略没有定义其自己的设置，则该策略包含用于所有策略的默认值。我们可以使用 `kopia policy show --global` 检查 `global` 策略：

```
$ kopia policy show --global
Policy for (global):
Keep:
  Annual snapshots:    3           (defined for this target)
  Monthly snapshots:  24           (defined for this target)
  Weekly snapshots:   25           (defined for this target)
  Daily snapshots:    14           (defined for this target)
  Hourly snapshots:   48           (defined for this target)
  Latest snapshots:   10           (defined for this target)

Files policy:
  No ignore rules.
  Read ignore rules from files:
    .kopiaignore                   (defined for this target)
```



我们可以使用 `kopia policy set` 命令更改策略设置。此命令允许您更改 `global` 策略或更改 `'user@host'`、`'@host'`、`'user@host:path'` 或特定目录的特定策略。

例如，在此处我们告诉 Kopia 设置策略以忽略将两个目录包含在 `jarek@jareks-mbp:/Users/jarek/Projects/Kopia/site` 的快照中：

```
$ kopia policy set --add-ignore public/ --add-ignore node_modules/ .
Setting policy for jarek@jareks-mbp:/Users/jarek/Projects/Kopia/site
 - adding public/ to ignored files
 - adding node_modules/ to ignored files
```

现在，在获取 `jarek@jareks-mbp:/Users/jarek/Projects/Kopia/site` 的快照时，将跳过目录 `public/` 和 `node_modules/`。



`kopia policy set` 命令帮助文档提供了有关您拥有的所有策略选项的更多信息。作为另一个例子，我们可以设置每周快照的最大数量：

```
$ kopia policy set --keep-weekly 30 .
Setting policy for jarek@jareks-mbp:/Users/jarek/Projects/Kopia/site
 - setting number of weekly backups to keep to 30.
```



如果您想检查特定目录的策略，请使用 `kopia policy show`：

```
$ kopia policy show .
Policy for jarek@jareks-mbp:/Users/jarek/Projects/Kopia/site:
Keep:
  Annual snapshots:    3           inherited from (global)
  Monthly snapshots:  24           inherited from (global)
  Weekly snapshots:   30           (defined for this target)
  Daily snapshots:    14           inherited from (global)
  Hourly snapshots:   48           inherited from (global)
  Latest snapshots:   10           inherited from (global)

Files policy:
  Ignore rules:
    dist/                          (defined for this target)
    node_modules/                  (defined for this target)
    public/                        (defined for this target)
  Read ignore rules from files:
    .kopiaignore                   inherited from (global)
```



要列出 `repository` 的所有策略，我们可以使用 `kopia policy list`：

```
$ kopia policy list
7898f47e36bad80a6d5d90f06ef16de6 (global)
63fc854c283ad63cafbca54eaa4509e9 jarek@jareks-mbp:/Users/jarek/Projects/Kopia/site
2339ab4739bb29688bf26a3a841cf68f jarek@jareks-mbp:/Users/jarek/Projects/Kopia/site/node_modules
```



最后，您还可以使用 `kopia policy import` 和 `kopia policy export` 命令导入和导出策略：

```
$ kopia policy import --from-file import.json
$ kopia policy export --to-file export.json
```



在上述示例中，`import.json` 和 `export.json` 共享相同的格式，这是策略标识符到定义策略的 JSON 映射，例如：

```
{
  "(global)": {
    "retention": {
      "keepLatest": 10,
      "keepHourly": 48,
      ...
    },
    ...
  },
  "foo@bar:/home/foobar": {
     "retention": {
      "keepLatest": 5,
      "keepHourly": 24,
      ...
    },
    ...
  }
}
```



您可以选择通过将策略标识符指定为 `kopia policy import` 和 `kopia policy export` 命令的参数来限制导入或导出哪些策略：

```
$ kopia policy import --from-file import.json "(global)" "foo@bar:/home/foobar"
$ kopia policy export --to-file export.json "(global)" "foo@bar:/home/foobar"
```



这两个命令都支持使用 stdin/stdout：

```
$ cat file.json | kopia policy import
$ kopia policy export > file.json
```



您可以使用 `--delete-other-policies` 标志删除所有未导入的策略。此命令将删除除 `(global)` 和 `foo@bar:/home/foobar` 之外的任何策略：

```
$ kopia policy import --from-file import.json --delete-other-policies "(global)" "foo@bar:/home/foobar"
```



### 缓存

为了获得更好的性能，Kopia 维护了本地缓存目录，其中存储了最近最常使用的块。您可以使用 `kopia cache info` 检查缓存：

```
$ kopia cache info
/Users/jarek/Library/Caches/kopia/e470f963ef9528a1/contents: 3 files 7 KB (limit 5.2 GB)
/Users/jarek/Library/Caches/kopia/e470f963ef9528a1/indexes: 12 files 670.8 KB
/Users/jarek/Library/Caches/kopia/e470f963ef9528a1/metadata: 2006 files 3.9 MB (limit 0 B)
```

要清除缓存，请使用 `kopia cache clear`：

```
$ kopia cache clear
```

要设置缓存参数，例如每个缓存的最大大小，请使用 `kopia cache set`：

```
$ kopia cache set --metadata-cache-size-mb=500
21:38:25.024 [kopia/cli] changing metadata cache size to 500 MB
```



### 仓库管理

在 Kopia CLI 中，管理、连接和切换多个存储库的核心逻辑是基于**配置文件 (Configuration Files)** 的。

默认情况下，当你不加任何特殊参数运行 `kopia repository connect` 时，Kopia 会将连接信息、缓存路径和加密密钥的派生信息保存在一个默认的全局配置文件中（例如在 Linux/macOS 上通常是 `~/.config/kopia/repository.config`）。这意味着默认状态下，Kopia CLI 只能同时连接一个存储库。



在 Linux/macOS 上，连接到仓库后，会在 `~/.config/kopia/`  路径中创建三个文件夹。



当创建一个新的仓库时，kopia 会自动断开当前仓库的连接（如有），然后自动连接到新创建的仓库中。当想要断开当前仓库的连接时，可以使用 kopia repository disconnect 命令。断开仓库连接后，kopia 会自动清除 `~/.config/kopia/` 目录中存储配置和密钥的文件。



