## 克隆现有的仓库

如果你想获得一份已经存在了的 Git 仓库的拷贝，可以用到 `git clone` 命令。 



### 默认名称

克隆仓库的命令是 `git clone <url>` 。 例如：

```console
$ git clone https://github.com/libgit2/libgit2
```



### 自定义名称

如果你想在克隆远程仓库的时候，自定义本地仓库的名字，你可以通过额外的参数指定新的目录名：

```console
$ git clone https://github.com/libgit2/libgit2 mylibgit
```



## 在已存在目录中初始化仓库

如果你有一个尚未进行版本控制的项目目录，想要用 Git 来控制它，那么首先需要进入该项目目录中。

执行：

```console
git init
```



# 跟踪新文件

使用命令 `git add` 开始跟踪一个文件。 所以，要跟踪 `README` 文件，运行：

```console
$ git add README
```



如果你想要跟踪工作目录中的所有文件，则可以在工作目录中的根目录中执行

注意：git不会跟踪空文件夹

```
git add .
```



# 状态预览

使用 `git status` 命令可以进行状态预览

```
git status
```

未跟踪的文件出现在 `Untracked files` 下面。

已暂存的文件出现在`Changes to be committed` 下面。

已修改未暂存的文件出现在 `Changes not staged for commit` 下面。





# 暂存已修改的文件

将一个已跟踪的文件进行修改后，需要执行`git add` 命令将文件放入暂存区，每次进行一次修改就要执行这条命令，因为git在提交的时候，只会提交最后一次执行该命令被放入暂存区的文件版本。

```
git add
```



# .gitignore 文件

.gitignore 文件用于列出要忽略的文件模式，通常是自动生成的文件，如日志文件或编译过程中的临时文件。



## 格式规范

- 所有空行或以 # 开头的行都会被 Git 忽略。
- 可以使用标准的 glob 模式匹配，递归应用在整个工作区。
- 匹配模式可以以（/）开头防止递归。
- 匹配模式可以以（/）结尾指定目录。
- 要忽略指定模式以外的文件或目录，可以在模式前加上叹号（!）取反。



## glob 模式

glob 模式是 shell 使用的简化正则表达式。例如，星号（*）匹配零个或多个任意字符；[abc] 匹配任何一个列在方括号中的字符；问号（?）只匹配一个任意字符；[0-9] 表示匹配所有 0 到 9 的数字。使用两个星号（******）表示匹配任意中间目录，如 a/******/z 可以匹配 a/z、a/b/z 或 a/b/c/z 等。



## .gitignore 文件示例

```gitignore
# 忽略所有的 .a 文件
*.a

# 但跟踪所有的 lib.a，即便你在前面忽略了 .a 文件
!lib.a

# 只忽略当前目录下的 TODO 文件，而不忽略 subdir/TODO
/TODO

# 忽略任何目录下名为 build 的文件夹
build/

# 忽略 doc/notes.txt，但不忽略 doc/server/arch.txt
doc/*.txt

# 忽略 doc/ 目录及其所有子目录下的 .pdf 文件
doc/**/*.pdf
```



在最简单的情况下，一个仓库可能只根目录下有一个 `.gitignore` 文件，它递归地应用到整个仓库中。 然而，子目录下也可以有额外的 `.gitignore` 文件。子目录中的 `.gitignore` 文件中的规则只作用于它所在的目录中。



# diff命令



## git diff

`git diff`命令用于比较工作目录中当前文件（修改后但未提交到暂存区）和暂存区文件的差异。



## git diff --staged

`git diff --staged`命令用于比对已暂存文件与最后一次提交的文件差异





## 从磁盘移除文件

如果只是简单地从工作目录中手工删除文件

运行 `git status` 时就会在 “Changes not staged for commit” 部分（也就是 *未暂存清单*）看到

然后再运行 `git rm` 记录此次移除文件的操作：

```console
#手动从磁盘删除文件
git rm 文件
```



## 移除已修改的文件

如果要**删除之前修改过**或**已经放到暂存区**的文件，则必须使用强制删除选项 `-f`（译注：即 force 的首字母）。 这是一种安全特性，用于防止误删尚未添加到快照的数据，这样的数据不能被 Git 恢复。



## 取消跟踪文件

不从磁盘中删除文件，使用 `--cached` 选项：

```
git rm --cached README
```



## 删除文件夹

使用`-r`选项





# 移动文件

移动（修改名称）文件或文件夹

```console
$ git mv file_from file_to
```

它会恰如预期般正常工作。 实际上，即便此时查看状态信息，也会明白无误地看到关于重命名操作的说明：

```console
$ git mv README.md README
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    renamed:    README.md -> README
```



其实，运行 `git mv` 就相当于运行了下面三条命令：

```console
$ mv README.md README
$ git rm README.md
$ git add README
```



## 在工作目录中移动

如果是直接通过文件管理器而不是`git mv`的方式移动了文件，则`git status`会认为是在源路径删除了文件，在目标路径新增了文件。

此时则需要通过 `git add` 和 `git rm` 手动跟踪文件和取消跟踪文件





# 查看提交历史

`git log` 命令

列出每个提交的 SHA-1 校验和、作者的名字和电子邮件地址、提交时间以及提交说明。



## --patch

`-p` 或 `--patch` ，它会显示每次提交所引入的差异（按 **补丁** 的格式输出）。 你也可以限制显示的日志条目数量，例如使用 `-2` 选项来只显示最近的两次提交：

```
$ git log -p -2
commit ca82a6dff817ec66f44342007202690a93763949
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Mon Mar 17 21:52:11 2008 -0700

    changed the version number

diff --git a/Rakefile b/Rakefile
index a874b73..8f94139 100644
--- a/Rakefile
+++ b/Rakefile
@@ -5,7 +5,7 @@ require 'rake/gempackagetask'
 spec = Gem::Specification.new do |s|
     s.platform  =   Gem::Platform::RUBY
     s.name      =   "simplegit"
-    s.version   =   "0.1.0"
+    s.version   =   "0.1.1"
     s.author    =   "Scott Chacon"
     s.email     =   "schacon@gee-mail.com"
     s.summary   =   "A simple gem for using Git in Ruby code."

commit 085bb3bcb608e1e8451d4b2432f8ecbe6306e7e7
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Sat Mar 15 16:40:33 2008 -0700

    removed unnecessary test

diff --git a/lib/simplegit.rb b/lib/simplegit.rb
index a0a60ae..47c6340 100644
--- a/lib/simplegit.rb
+++ b/lib/simplegit.rb
@@ -18,8 +18,3 @@ class SimpleGit
     end

 end
-
-if $0 == __FILE__
-  git = SimpleGit.new
-  puts git.show
-end
```



##  --stat

`--stat` 选项，以为 `git log` 附带一系列的总结性选项。 

```
C:\Users\Xiaoshae\Desktop\文档>git log --stat -2
commit 41ae8362e5572f577cda9b8fdf49981c9a5e2c31 (HEAD -> master)
Author: Xiaoshae <xiaoshae@gmail.com>
Date:   Thu Jan 4 14:30:20 2024 +0800

    version 3.0.0 to add rm and mv

 Git/Git mini.md |  83 ++++++++++++++++++++++++++++++++++++++++++
 Git/Git.md      | 109 +++++++++++++++++++++++++++++++++++++++++++++++++++++++-
 2 files changed, 191 insertions(+), 1 deletion(-)

commit dd46045796baebdfe1ec0698b2d4dfe8e427c9ce
Author: Xiaoshae <xiaoshae@gmail.com>
Date:   Thu Jan 4 14:07:18 2024 +0800

    to git diff and git diff --cached

 Git/Git mini.md | 148 +++++++++++++++++++++++++++++
 Git/Git.md      | 284 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 432 insertions(+)
```



##  --pretty

`--pretty`。 这个选项可以使用不同于默认格式的方式展示提交历史。

`oneline` 会将每个提交放在一行显示

另外还有 `short`，`full` 和 `fuller` 选项，它们展示信息的格式基本一致，但是详尽程度不一：



### oneline

```
git log --pretty=oneline
ca82a6dff817ec66f44342007202690a93763949 changed the version number
085bb3bcb608e1e8451d4b2432f8ecbe6306e7e7 removed unnecessary test
a11bef06a3f659402fe7563abf99ad00de2209e6 first commit
```



### format

可以定制记录的显示格式。

```
git log --pretty=format:"%h - %an, %ar : %s"
ca82a6d - Scott Chacon, 6 years ago : changed the version number
085bb3b - Scott Chacon, 6 years ago : removed unnecessary test
a11bef0 - Scott Chacon, 6 years ago : first commit
```

| 选项  | 说明                                          |
| :---- | :-------------------------------------------- |
| `%H`  | 提交的完整哈希值                              |
| `%h`  | 提交的简写哈希值                              |
| `%T`  | 树的完整哈希值                                |
| `%t`  | 树的简写哈希值                                |
| `%P`  | 父提交的完整哈希值                            |
| `%p`  | 父提交的简写哈希值                            |
| `%an` | 作者名字                                      |
| `%ae` | 作者的电子邮件地址                            |
| `%ad` | 作者修订日期（可以用 --date=选项 来定制格式） |
| `%ar` | 作者修订日期，按多久以前的方式显示            |
| `%cn` | 提交者的名字                                  |
| `%ce` | 提交者的电子邮件地址                          |
| `%cd` | 提交日期                                      |
| `%cr` | 提交日期（距今多长时间）                      |
| `%s`  | 提交说明                                      |



## graph

当 `oneline` 或 `format` 与另一个 `log` 选项 `--graph` 结合使用。 

添加了一些 ASCII 字符串来形象地展示你的分支、合并历史

```console
$ git log --pretty=format:"%h %s" --graph
* 2d3acf9 ignore errors from SIGCHLD on trap
*  5e3ee11 Merge branch 'master' of git://github.com/dustin/grit
|\
| * 420eac9 Added a method for getting the current branch.
* | 30e367c timeout code and tests
* | 5a09431 add timeout protection to grit
* | e1193f8 support for heads with slashes in them
|/
* d6016bc require time for xmlschema
*  11d191e Merge branch 'defunkt' into local
```



## git log 其他常用

| 选项              | 说明                                                         |
| :---------------- | :----------------------------------------------------------- |
| `-p`              | 按补丁格式显示每个提交引入的差异。                           |
| `--stat`          | 显示每次提交的文件修改统计信息。                             |
| `--shortstat`     | 只显示 --stat 中最后的行数修改添加移除统计。                 |
| `--name-only`     | 仅在提交信息后显示已修改的文件清单。                         |
| `--name-status`   | 显示新增、修改、删除的文件清单。                             |
| `--abbrev-commit` | 仅显示 SHA-1 校验和所有 40 个字符中的前几个字符。            |
| `--relative-date` | 使用较短的相对时间而不是完整格式显示日期（比如“2 weeks ago”）。 |
| `--graph`         | 在日志旁以 ASCII 图形显示分支与合并历史。                    |
| `--pretty`        | 使用其他格式显示历史提交信息。可用的选项包括 oneline、short、full、fuller 和 format（用来定义自己的格式）。 |
| `--oneline`       | `--pretty=oneline --abbrev-commit` 合用的简写。              |



## 限制输出长度

`git log`  使用类似 `-<n>` 的选项，其中的 `n` 可以是任何整数，表示仅显示最近的 `n` 条提交。 

类似 `--since` 和 `--until` 这种按照时间作限制的选项很有用。

 例如，下面的命令会列出最近两周的所有提交：

```console
git log --since=2.weeks
```

该命令可用的格式十分丰富——可以是类似 `"2008-01-15"` 的具体的某一天，也可以是类似 `"2 years 1 day 3 minutes ago"` 的相对日期。

用 `--author` 选项显示指定作者的提交，用 `--grep` 选项搜索提交说明中的关键字。



### 限制 `git log` 输出的选项

| 选项              | 说明                                       |
| ----------------- | ------------------------------------------ |
| -<n>              | 仅显示最近的 n 条提交。                    |
| --since, --after  | 仅显示指定时间之后的提交。                 |
| --until, --before | 仅显示指定时间之前的提交。                 |
| --author          | 仅显示作者匹配指定字符串的提交。           |
| --committer       | 仅显示提交者匹配指定字符串的提交。         |
| --grep            | 仅显示提交说明中包含指定字符串的提交。     |
| -S                | 仅显示添加或删除内容匹配指定字符串的提交。 |



# 作者和提交者区别

*作者* 和 *提交者* 之间究竟有何差别， 其实作者指的是实际作出修改的人，提交者指的是最后将此工作成果提交到仓库的人。 所以，当你为某个项目发布补丁，然后某个核心成员将你的补丁并入项目时，你就是作者，而那个核心成员就是提交者。





# 撤销操作

## 提交覆盖

 `--amend` 命令会将暂存区中的文件提交，覆盖上一次提交。

 如果自上次提交以来你还未做任何修改（例如，在上次提交后马上执行了此命令）， 那么快照会保持不变，而你所修改的只是提交信息。

```console
$ git commit --amend
```



## 取消暂存的文件

使用 `git reset HEAD <file>…` 来取消暂存。 将文件从暂存区中移除

```
git reset HEAD <file>
```



## 撤消对文件的修改

`git checkout — <file>` 将指定的文件还原成上次提交时的版本。

```console
git checkout — <file>
```





# 远程仓库

## 查看远程仓库

`git remote` 命令,列出你指定的每一个远程服务器的简写。

选项 `-v`，会显示需要读写远程仓库使用的 Git 保存的简写与其对应的 URL。

```
git remote
git remote -v
```





## 添加远程仓库

 `git remote add <shortname> <url>` 添加一个新的远程 Git 仓库，同时指定一个方便使用的简写：

```console
git remote add 
```





## 从远程仓库中抓取与拉取

`git fetch <remote>`从远程仓库中获得数据，可以执行：

```console
git fetch
```

`git pull` 命令来自动抓取后合并该远程分支到当前分支。

```
git pull
```



## 查看某个远程仓库

 `git remote show <remote>` 命令查看某一个远程仓库的更多信息

```console
git remote show
```



## 远程仓库的重命名与移除

 `git remote rename <oldName> <newName>` 来修改一个远程仓库的简写名。

```console
git remove rename
```



# 打标签

Git 可以给仓库历史中的某一个提交打上标签。

## 列出标签

 `git tag` （可带上可选的 `-l` 选项 `--list`）：

```console
git tag
```

 `-l` 或 `--list` 选项，列出一个列表。

筛选标签

```
git tag -l "v1.8.5*"
```



## 创建标签



**轻量标签**：轻量标签很像一个不会改变的分支，它只是某个特定提交的引用1。

```shell
git tag {标签名} #{提交ID}
```



**附注标签**：可以被校验，包含打标签者的名字、电子邮件地址、日期时间，此外还有一个标签信息，可以使用GPG签名并验证。

```shell
git tag -a {标签名} -m "{标签信息}" #{提交ID}
```



### 后期标签

你也可以对过去的提交打标签。如果不指定提交ID，则标签会打在最新的一次提交上，也可以通过标签ID来指定该标签打在过去提交的标签上。



## 共享标签

git push` 命令并不会传送标签到远程仓库服务器上。

```
 git push <remote> <tagname>
```

 `--tags` 选项，这将会把所有不在远程仓库服务器上的标签全部传送到那里。推送标签并不会区分轻量标签和附注标签。



## 删除标签

要删除掉你本地仓库上的标签，可以使用命令 `git tag -d <tagname>`。

```console
git tag -d v1.4-lw
```



 `git push <remote> :refs/tags/<tagname>` 更新你的远程仓库：

```
git push <remote> :refs/tags/<tagname>
```



删除远程标签的方式是：

```console
$ git push origin --delete <tagname>
```



## 检出标签

`git checkout` 命令查看某个标签所指向的文件版本

```console
git checkout <tagname>
```

