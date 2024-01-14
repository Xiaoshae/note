# 三种状态

现在请注意，如果你希望后面的学习更顺利，请记住下面这些关于 Git 的概念。 Git 有三种状态，你的文件可能处于其中之一： **已提交（committed）**、**已修改（modified）** 和 **已暂存（staged）**。

- 已修改表示修改了文件，但还没保存到数据库中。
- 已暂存表示对一个已修改文件的当前版本做了标记，使之包含在下次提交的快照中。
- 已提交表示数据已经安全地保存在本地数据库中。



# 获取 Git 仓库

通常有两种获取 Git 项目仓库的方式：

1. 从其它服务器 **克隆** 一个已存在的 Git 仓库。
2. 将尚未进行版本控制的本地目录转换为 Git 仓库；



## 克隆现有的仓库

如果你想获得一份已经存在了的 Git 仓库的拷贝，比如说，你想为某个开源项目贡献自己的一份力，这时就要用到 `git clone` 命令。 

Git 克隆的是该 Git 仓库服务器上的几乎所有数据，而不是仅仅复制完成你的工作所需要文件。 当你执行 `git clone` 命令的时候，默认配置下远程 Git 仓库中的每一个文件的每一个版本都将被拉取下来。



### 默认名称

克隆仓库的命令是 `git clone <url>` 。 比如，要克隆 Git 的链接库 `libgit2`，可以用下面的命令：

```console
$ git clone https://github.com/libgit2/libgit2
```

这会在当前目录下创建一个名为 “libgit2” 的目录，并在这个目录下初始化一个 `.git` 文件夹， 从远程仓库拉取下所有数据放入 `.git` 文件夹，然后从中读取最新版本的文件的拷贝。 



### 自定义名称

如果你想在克隆远程仓库的时候，自定义本地仓库的名字，你可以通过额外的参数指定新的目录名：

```console
$ git clone https://github.com/libgit2/libgit2 mylibgit
```

这会执行与上一条命令相同的操作，但目标目录名变为了 `mylibgit`。



## 在已存在目录中初始化仓库

如果你有一个尚未进行版本控制的项目目录，想要用 Git 来控制它，那么首先需要进入该项目目录中。

执行：

```console
git init
```

该命令将创建一个名为 `.git` 的子目录，这个子目录含有你初始化的 Git 仓库中所有的必须文件，这些文件是 Git 仓库的骨干。 但是，在这个时候，我们仅仅是做了一个初始化的操作，你的项目里的文件还没有被跟踪。



# 跟踪新文件

使用命令 `git add` 开始跟踪一个文件。 所以，要跟踪 `README` 文件，运行：

```console
$ git add README
```



此时运行 `git status` 命令，会看到 `README` 文件已被跟踪，并处于暂存状态：

只要在 `Changes to be committed` 这行下面的，就说明是已暂存状态。

```console
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)

    new file:   README
```



如果你想要跟踪工作目录中的所有文件，则可以在工作目录中的根目录中执行

注意：git不会跟踪空文件夹

```
git add .
```



# 状态预览

# 暂存已修改的文件

现在我们来修改一个已被跟踪的文件。 如果你修改了一个名为 `CONTRIBUTING.md` 的已被跟踪的文件，然后运行 `git status` 命令，会看到下面内容：



文件 `CONTRIBUTING.md` 出现在 `Changes not staged for commit` 这行下面，说明已跟踪文件的内容发生了变化，但还没有放到暂存区。 要暂存这次更新，需要运行 `git add` 命令。 

`git add` 是个多功能命令：可以用它开始跟踪新文件，或者把已跟踪的文件放到暂存区，还能用于合并时把有冲突的文件标记为已解决状态等。

```console
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    new file:   README

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

    modified:   CONTRIBUTING.md
```



运行 `git add` 将“CONTRIBUTING.md”放到暂存区，然后再看看 `git status` 的输出：

现在两个文件都已暂存，下次提交时就会一并记录到仓库。

```console
$ git add CONTRIBUTING.md
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    new file:   README
    modified:   CONTRIBUTING.md
```



 假设此时，你想要在 `CONTRIBUTING.md` 里再加条注释。 重新编辑存盘后，准备好提交。 不过且慢，再运行 `git status` 看看：

现在 `CONTRIBUTING.md` 文件同时出现在暂存区和非暂存区。实际上 Git 只不过暂存了你运行 `git add` 命令时的版本。 如果你现在提交，`CONTRIBUTING.md` 的版本是你最后一次运行 `git add` 命令时的那个版本，而不是你运行 `git commit` 时，在工作目录中的当前版本。

```console
$ vim CONTRIBUTING.md
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    new file:   README
    modified:   CONTRIBUTING.md

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

    modified:   CONTRIBUTING.md
```



重新运行 `git add` 把最新版本重新暂存起来：

```console
$ git add CONTRIBUTING.md
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    new file:   README
    modified:   CONTRIBUTING.md
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



如果只是简单地从工作目录中手工删除文件，运行 `git status` 时就会在 “Changes not staged for commit” 部分（也就是 *未暂存清单*）看到：

```console
$ rm PROJECTS.md
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        deleted:    PROJECTS.md

no changes added to commit (use "git add" and/or "git commit -a")
```

然后再运行 `git rm` 记录此次移除文件的操作：

```console
$ git rm PROJECTS.md
rm 'PROJECTS.md'
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    deleted:    PROJECTS.md
```

下一次提交时，该文件就不再纳入版本管理了。



### 移除文件



## 从磁盘移除文件

如果只是简单地从工作目录中手工删除文件，运行 `git status` 时就会在 “Changes not staged for commit” 部分（也就是 *未暂存清单*）看到：

```console
$ rm PROJECTS.md
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        deleted:    PROJECTS.md

no changes added to commit (use "git add" and/or "git commit -a")
```

然后再运行 `git rm` 记录此次移除文件的操作：

```console
$ git rm PROJECTS.md
rm 'PROJECTS.md'
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    deleted:    PROJECTS.md
```



## 移除已修改的文件

如果要**删除之前修改过**或**已经放到暂存区**的文件，则必须使用强制删除选项 `-f`（译注：即 force 的首字母）。 这是一种安全特性，用于防止误删尚未添加到快照的数据，这样的数据不能被 Git 恢复。



## 取消跟踪文件

另外一种情况是，我们想把文件从 Git 仓库中删除（亦即从暂存区域移除），但仍然希望保留在当前工作目录中。 

换句话说，你想让文件保留在磁盘，但是并不想让 Git 继续跟踪。

使用 `--cached` 选项：

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



#  查看提交历史

`git log` 命令，不传入任何参数的默认情况下，这个命令会按时间先后顺序列出所有的提交，最近的更新排在最上面。 正如你所看到的，这个命令会列出每个提交的 SHA-1 校验和、作者的名字和电子邮件地址、提交时间以及提交说明。



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

`--stat` 选项，以为 `git log` 附带一系列的总结性选项。 比如你想看到每次提交的简略统计信息。

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

`--pretty`。 这个选项可以使用不同于默认格式的方式展示提交历史。 这个选项有一些内建的子选项供你使用。 比如 `oneline` 会将每个提交放在一行显示，在浏览大量的提交时非常有用。 另外还有 `short`，`full` 和 `fuller` 选项，它们展示信息的格式基本一致，但是详尽程度不一：



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

当 `oneline` 或 `format` 与另一个 `log` 选项 `--graph` 结合使用时尤其有用。 这个选项添加了一些 ASCII 字符串来形象地展示你的分支、合并历史

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

`git log` 还有许多非常实用的限制输出长度的选项，也就是只输出一部分的提交。 实际上，你可以使用类似 `-<n>` 的选项，其中的 `n` 可以是任何整数，表示仅显示最近的 `n` 条提交。 

类似 `--since` 和 `--until` 这种按照时间作限制的选项很有用。 例如，下面的命令会列出最近两周的所有提交：

```console
git log --since=2.weeks
```

该命令可用的格式十分丰富——可以是类似 `"2008-01-15"` 的具体的某一天，也可以是类似 `"2 years 1 day 3 minutes ago"` 的相对日期。



还可以过滤出匹配指定条件的提交。 用 `--author` 选项显示指定作者的提交，用 `--grep` 选项搜索提交说明中的关键字。



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



# 撤消操作

在任何一个阶段，你都有可能想要撤消某些操作。 这里，我们将会学习几个撤消你所做修改的基本工具。 注意，有些撤消操作是不可逆的。 这是在使用 Git 的过程中，会因为操作失误而导致之前的工作丢失的少有的几个地方之一。



## 提交覆盖

有时候我们提交完了才发现漏掉了几个文件没有添加，或者提交信息写错了。 此时，可以运行带有 `--amend` 选项的提交命令来重新提交：

```console
$ git commit --amend
```

这个命令会将暂存区中的文件提交。 如果自上次提交以来你还未做任何修改（例如，在上次提交后马上执行了此命令）， 那么快照会保持不变，而你所修改的只是提交信息。

文本编辑器启动后，可以看到之前的提交信息。 编辑后保存会覆盖原来的提交信息。

例如，你提交后发现忘记了暂存某些需要的修改，可以像下面这样操作：

```console
$ git commit -m 'initial commit'
$ git add forgotten_file
$ git commit --amend
```

最终你只会有一个提交——第二次提交将代替第一次提交的结果。



当你在修补最后的提交时，与其说是修复旧提交，倒不如说是完全用一个 **新的提交** 替换旧的提交， 理解这一点非常重要。从效果上来说，就像是旧有的提交从未存在过一样，它并不会出现在仓库的历史中。



## 取消暂存的文件

接下来的两个小节演示如何操作暂存区和工作目录中已修改的文件。 这些命令在修改文件状态的同时，也会提示如何撤消操作。 例如，你已经修改了两个文件并且想要将它们作为两次独立的修改提交， 但是却意外地输入 `git add *` 暂存了它们两个。如何只取消暂存两个中的一个呢？ `git status` 命令提示了你：

```console
$ git add *
$ git status
On branch master
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    renamed:    README.md -> README
    modified:   CONTRIBUTING.md
```

在 “Changes to be committed” 文字正下方，提示使用 `git reset HEAD <file>…` 来取消暂存。 



## 撤消对文件的修改

如果你并不想保留对 `CONTRIBUTING.md` 文件的修改怎么办？ 你该如何方便地撤消修改——将它还原成上次提交时的样子（或者刚克隆完的样子，或者刚把它放入工作目录时的样子）？ 幸运的是，`git status` 也告诉了你应该如何做。 在最后一个例子中，未暂存区域是这样：

```console
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

    modified:   CONTRIBUTING.md
```

它非常清楚地告诉了你如何撤消之前所做的修改。 让我们来按照提示执行：

```console
$ git checkout -- CONTRIBUTING.md
$ git status
On branch master
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    renamed:    README.md -> README
```

可以看到那些修改已经被撤消了。



请务必记得 `git checkout — <file>` 是一个危险的命令。 你对那个文件在本地的任何修改都会消失——Git 会用最近提交的版本覆盖掉它。 除非你确实清楚不想要对那个文件的本地修改了，否则请不要使用这个命令。



# 远程仓库

## 查看远程仓库

`git remote` 命令,列出你指定的每一个远程服务器的简写。

 如果你已经克隆了自己的仓库，那么至少应该能看到 origin ——这是 Git 给你克隆的仓库服务器的默认名字：

```
git clone https://github.com/schacon/ticgit
Cloning into 'ticgit'...
remote: Reusing existing pack: 1857, done.
remote: Total 1857 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (1857/1857), 374.35 KiB | 268.00 KiB/s, done.
Resolving deltas: 100% (772/772), done.
Checking connectivity... done.
$ cd ticgit
$ git remote
origin
```



你也可以指定选项 `-v`，会显示需要读写远程仓库使用的 Git 保存的简写与其对应的 URL。

```console
$ git remote -v
origin	https://github.com/schacon/ticgit (fetch)
origin	https://github.com/schacon/ticgit (push)
```





## 添加远程仓库

 `git remote add <shortname> <url>` 添加一个新的远程 Git 仓库，同时指定一个方便使用的简写：

```console
$ git remote
origin
$ git remote add pb https://github.com/paulboone/ticgit
$ git remote -v
origin	https://github.com/schacon/ticgit (fetch)
origin	https://github.com/schacon/ticgit (push)
pb	https://github.com/paulboone/ticgit (fetch)
pb	https://github.com/paulboone/ticgit (push)
```

现在你可以在命令行中使用字符串 `pb` 来代替整个 URL。 例如，如果你想拉取 Paul 的仓库中有但你没有的信息，可以运行 `git fetch pb`：





## 从远程仓库中抓取与拉取

就如刚才所见，从远程仓库中获得数据，可以执行：

```console
$ git fetch <remote>
```

这个命令会访问远程仓库，从中拉取所有你还没有的数据。 执行完成后，你将会拥有那个远程仓库中所有分支的引用，可以随时合并或查看。

如果你使用 `clone` 命令克隆了一个仓库，命令会自动将其添加为远程仓库并默认以 “origin” 为简写。 所以，`git fetch origin` 会抓取克隆（或上一次抓取）后新推送的所有工作。 

必须注意 `git fetch` 命令只会将数据下载到你的本地仓库——它并不会自动合并或修改你当前的工作。 当准备好时你必须手动将其合并入你的工作。

`git pull` 命令来自动抓取后合并该远程分支到当前分支。，通常会从最初克隆的服务器上抓取数据并自动尝试合并到当前所在的分支。

`git clone` 命令默认会自动设置本地 master 分支跟踪克隆的远程仓库的 `master` 分支（或其它名字的默认分支）。 



## 查看某个远程仓库

 `git remote show <remote>` 命令查看某一个远程仓库的更多信息，如果想以一个特定的缩写名运行这个命令，例如 `origin`，会得到像下面类似的信息：

```console
$ git remote show origin
* remote origin
  Fetch URL: https://github.com/schacon/ticgit
  Push  URL: https://github.com/schacon/ticgit
  HEAD branch: master
  Remote branches:
    master                               tracked
    dev-branch                           tracked
  Local branch configured for 'git pull':
    master merges with remote master
  Local ref configured for 'git push':
    master pushes to master (up to date)
```



它同样会列出远程仓库的 URL 与跟踪分支的信息。 这些信息非常有用，它告诉你正处于 `master` 分支，并且如果运行 `git pull`， 就会抓取所有的远程引用，然后将远程 `master` 分支合并到本地 `master` 分支。 它也会列出拉取到的所有远程引用。

这是一个经常遇到的简单例子。 如果你是 Git 的重度使用者，那么还可以通过 `git remote show` 看到更多的信息。

```console
$ git remote show origin
* remote origin
  URL: https://github.com/my-org/complex-project
  Fetch URL: https://github.com/my-org/complex-project
  Push  URL: https://github.com/my-org/complex-project
  HEAD branch: master
  Remote branches:
    master                           tracked
    dev-branch                       tracked
    markdown-strip                   tracked
    issue-43                         new (next fetch will store in remotes/origin)
    issue-45                         new (next fetch will store in remotes/origin)
    refs/remotes/origin/issue-11     stale (use 'git remote prune' to remove)
  Local branches configured for 'git pull':
    dev-branch merges with remote dev-branch
    master     merges with remote master
  Local refs configured for 'git push':
    dev-branch                     pushes to dev-branch                     (up to date)
    markdown-strip                 pushes to markdown-strip                 (up to date)
    master                         pushes to master                         (up to date)
```

这个命令列出了当你在特定的分支上执行 `git push` 会自动地推送到哪一个远程分支。 它也同样地列出了哪些远程分支不在你的本地，哪些远程分支已经从服务器上移除了， 还有当你执行 `git pull` 时哪些本地分支可以与它跟踪的远程分支自动合并。



## 远程仓库的重命名与移除

你可以运行 `git remote rename` 来修改一个远程仓库的简写名。 例如，想要将 `pb` 重命名为 `paul`，可以用 `git remote rename` 这样做：

```console
$ git remote rename pb paul
$ git remote
origin
paul
```

值得注意的是这同样也会修改你所有远程跟踪的分支名字。 那些过去引用 `pb/master` 的现在会引用 `paul/master`。

如果因为一些原因想要移除一个远程仓库——你已经从服务器上搬走了或不再想使用某一个特定的镜像了， 又或者某一个贡献者不再贡献了——可以使用 `git remote remove` 或 `git remote rm` ：

```console
$ git remote remove paul
$ git remote
origin
```

一旦你使用这种方式删除了一个远程仓库，那么所有和这个远程仓库相关的远程跟踪分支以及配置信息也会一起被删除。



# 打标签

Git 可以给仓库历史中的某一个提交打上标签，以示重要。 比较有代表性的是人们会使用这个功能来标记发布结点（ `v1.0` 、 `v2.0` 等等）。



## 列出标签

在 Git 中列出已有的标签非常简单，只需要输入 `git tag` （可带上可选的 `-l` 选项 `--list`）：

```console
$ git tag
v1.0
v2.0
```

这个命令以字母顺序列出标签，但是它们显示的顺序并不重要。

你也可以按照特定的模式查找标签。 例如，Git 自身的源代码仓库包含标签的数量超过 500 个。 如果只对 1.8.5 系列感兴趣，可以运行：

```console
$ git tag -l "v1.8.5*"
v1.8.5
v1.8.5-rc0
v1.8.5-rc1
v1.8.5-rc2
v1.8.5-rc3
v1.8.5.1
v1.8.5.2
v1.8.5.3
v1.8.5.4
v1.8.5.5
```

Note  按照通配符列出标签需要 `-l` 或 `--list` 选项如果你只想要完整的标签列表，那么运行 `git tag` 就会默认假定你想要一个列表，它会直接给你列出来， 此时的 `-l` 或 `--list` 是可选的。

如果你提供了一个匹配标签名的通配模式，那么 `-l` 或 `--list` 就是强制使用的。





## 创建标签

Git 支持两种标签：轻量标签（lightweight）与附注标签（annotated）。



**轻量标签**：轻量标签很像一个不会改变的分支——它只是某个特定提交的引用1。创建轻量标签的命令如下：

```shell
git tag {标签名} #{提交ID}
```

例如，创建一个指向最新提交的轻量标签：

```shell
git tag v1.0.0
```



**附注标签**：附注标签是存储在Git数据库中的一个完整对象，它们是可以被校验的，其中包含打标签者的名字、电子邮件地址、日期时间，此外还有一个标签信息，并且可以使用GNU Privacy Guard（GPG）签名并验证1。创建附注标签的命令如下

```shell
git tag -a {标签名} -m "{标签信息}" #{提交ID}
```

例如，创建一个指向最新提交的附注标签：

```shell
git tag -a v1.0.0 -m "Release version 1.0.0" HEAD
```



### 后期标签

你也可以对过去的提交打标签。如果不指定提交ID，则标签会打在最新的一次提交上，也可以通过标签ID来指定该标签打在过去提交的标签上。



## 共享标签

默认情况下，`git push` 命令并不会传送标签到远程仓库服务器上。在创建完标签后你必须显式地推送标签到共享服务器上。 

```
 git push <remote> <tagname>
```



 `--tags` 选项，这将会把所有不在远程仓库服务器上的标签全部传送到那里。

使用 `git push <remote> --tags` 推送标签并不会区分轻量标签和附注标签， 没有简单的选项能够让你只选择推送一种标签。

```console
git push origin --tags
Counting objects: 1, done.
Writing objects: 100% (1/1), 160 bytes | 0 bytes/s, done.
Total 1 (delta 0), reused 0 (delta 0)
To git@github.com:schacon/simplegit.git
 * [new tag]         v1.4 -> v1.4
 * [new tag]         v1.4-lw -> v1.4-lw
```



## 删除标签

要删除掉你本地仓库上的标签，可以使用命令 `git tag -d <tagname>`。

不会从任何远程仓库中移除这个标签，你必须用 `git push <remote> :refs/tags/<tagname>` 来更新

```console
git tag -d v1.4-lw
```



你必须用 `git push <remote> :refs/tags/<tagname>` 来更新你的远程仓库：

```
git push <remote> :refs/tags/<tagname>
```



第一种变体是 `git push <remote> :refs/tags/<tagname>` ：

```console
$ git push origin :refs/tags/v1.4-lw
To /git@github.com:schacon/simplegit.git
 - [deleted]         v1.4-lw
```

- `<remote>`是你想要推送到的远程仓库的名称，例如`origin`。
- `:refs/tags/<tagname>`是你想要删除的远程标签的引用，例如`:refs/tags/v1.4-lw`。

在这个命令中，冒号前面的空值表示你想要将空值（也就是没有任何内容）推送到远程标签名，这样就可以删除远程仓库中的对应标签。



第二种更直观的删除远程标签的方式是：

```console
$ git push origin --delete <tagname>
```



## 检出标签

如果你想查看某个标签所指向的文件版本，可以使用 `git checkout` 命令， 虽然这会使你的仓库处于“分离头指针（detached HEAD）”的状态——这个状态有些不好的副作用：

```console
$ git checkout 2.0.0
Note: checking out '2.0.0'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch>

HEAD is now at 99ada87... Merge pull request #89 from schacon/appendix-final

$ git checkout 2.0-beta-0.1
Previous HEAD position was 99ada87... Merge pull request #89 from schacon/appendix-final
HEAD is now at df3f601... add atlas.json and cover image
```

在“分离头指针”状态下，如果你做了某些更改然后提交它们，标签不会发生变化， 但你的新提交将不属于任何分支，并且将无法访问，除非通过确切的提交哈希才能访问。



 因此，如果你需要进行更改，比如你要修复旧版本中的错误，那么通常需要创建一个新分支：

```console
$ git checkout -b version2 v2.0.0
Switched to a new branch 'version2'
```

如果在这之后又进行了一次提交，`version2` 分支就会因为这个改动向前移动， 此时它就会和 `v2.0.0` 标签稍微有些不同，这时就要当心了。



# 命令别名

在 Git 中，你可以使用别名（alias）来简化命令。以下是一些常见的 Git 别名设置：

```bash
git config --global alias.co checkout
git config --global alias.ci commit
git config --global alias.st status
```

这意味着，例如，你可以使用 `git ci` 代替 `git commit`。用 `git st` 代替 `git status`



此外，你还可以创建自定义的别名。例如，为了解决取消暂存文件的问题，你可以添加一个 unstage 别名：

```bash
git config --global alias.unstage 'reset HEAD --'
```

这会使以下两个命令等价：

```bash
git unstage fileA
git reset HEAD -- fileA
```



通常，人们还会添加一个 `last` 命令，以便轻松查看最后一次提交：

```bash
git config --global alias.last 'log -1 HEAD'
```



此外，如果你想要执行外部命令，而不是 Git 子命令，你可以在命令前面加上 `!` 符号。例如，你可以将 `git visual` 定义为 `gitk` 的别名：

```bash
git config --global alias.visual '!gitk'
```



# 分支

Git 的分支模型为它的“必杀技特性”，也正因为这一特性，使得 Git 从众多版本控制系统中脱颖而出。 Git 处理分支的方式可谓是难以置信的轻量，创建新分支这一操作几乎能在瞬间完成。 与许多其它版本控制系统不同，Git 鼓励在工作流程中频繁地使用分支与合并。 

## Git处理数据

为了真正理解 Git 处理分支的方式，我们需要回顾一下 Git 是如何保存数据的。

在进行提交操作时，Git 会保存一个提交对象（commit object）。提交对象会包含一个**指向暂存内容快照的指针**，还包含了**作者的姓名和邮箱、提交时输入的信息**以及**指向它的父对象的指针**。



假设现在有一个工作目录，里面**有三个**将要被暂存和提交的**文件**。

暂存操作会为每一个文件计算校验和，把当前版本的文件快照保存到 Git 仓库中（blob对象），加入到暂存区域等待提交。

提交操作时，Git 会先计算每一个子目录的校验和， 然后在 Git 仓库中这些校验和保存为树对象。

Git 便会创建一个提交对象， 它除了包含上面提到的那些信息外，还包含指向这个树对象（项目根目录）的指针。 

Git 仓库中有五个对象：三个 **blob** 对象（保存着文件快照）、一个 **树** 对象 （记录着目录结构和 blob 对象索引）以及一个 **提交** 对象（包含着指向前述树对象的指针和所有提交信息）。

![首次提交对象及其树结构。](images/Git.assets/commit-and-tree.png)



做些修改后再次提交，那么这次产生的提交对象会包含一个指向上次提交对象（父对象）的指针。

![提交对象及其父对象。](images/Git.assets/commits-and-parents.png)



Git 的分支，其实本质上仅仅是指向提交对象的可变指针。 Git 的默认分支名字是 `master`。 在多次提交操作之后，你其实已经有一个指向最后那个提交对象的 `master` 分支。 `master` 分支会在每次提交时自动向前移动。



Git 的 `master` 分支并不是一个特殊分支。 它就跟其它分支完全没有区别。 之所以几乎每一个仓库都有 master 分支，是因为 `git init` 命令默认创建它，并且大多数人都懒得去改动它。



## 分支创建

Git 是怎么创建新分支的呢？ 很简单，它只是为你创建了一个可以移动的新的指针。 比如，创建一个 testing 分支， 你需要使用 `git branch` 命令：

这会在**当前所在的提交对象**上创建一个指针（testing分支）。

```console
git branch testing
```

![两个指向相同提交历史的分支。](images/Git.assets/two-branches.png)





## HEAD指针

Git 有一个名为 `HEAD` 的特殊指针，指向当前所在的本地分支（译注：将 `HEAD` 想象为当前分支的别名）。 

在本例中，你仍然在 `master` 分支上。 因为 `git branch` 命令仅仅 **创建** 一个新分支，并不会自动切换到新分支中去。

![HEAD 指向当前所在的分支。](images/Git.assets/head-to-master.png)



## 分支当前所指的对象

 `git log` 命令`--decorate`参数查看各个分支当前所指的对象。

当前 `master` 和 `testing` 分支均指向校验和以 `f30ab` 开头的提交对象。

```console
$ git log --oneline --decorate
f30ab (HEAD -> master, testing) add feature #32 - ability to add new formats to the central interface
34ac2 Fixed bug #1328 - stack overflow under certain conditions
98ca9 The initial commit of my project
```



## 分支切换

 `git checkout` 命令切换到一个已存在的分支

现在切换到新创建的 `testing` 分支去，这样 `HEAD` 就指向 `testing` 分支了：

```console
$ git checkout testing
```

![HEAD 指向当前所在的分支。](images/Git.assets/head-to-testing.png)



## HEAD分支移动

现在不妨再提交一次。

如图所示，你的 `testing` 分支向前移动了，但是 `master` 分支却没有。

![HEAD 分支随着提交操作自动向前移动。](images/Git.assets/advance-testing.png)



切换回 `master` 分支看看：

使 HEAD 指回 `master` 分支，将工作目录恢复成 `master` 分支所指向的快照内容。

```console
git checkout master
```

![检出时 HEAD 随之移动。](images/Git.assets/checkout-master.png)



妨再稍微做些修改并提交：

这个项目的提交历史已经产生了分叉。

上述两次改动针对的是不同分支：你可以在不同分支间不断地来回切换和工作，并在时机成熟时将它们合并起来。 

![项目分叉历史。](images/Git.assets/advance-master.png)



## 快进合并

这是分支原本的模样

![`iss53` 分支随着工作的进展向前推进。](images/Git.assets/basic-branching-3.png)



这时切换回 `master` 分支了，然后建立一个 `hotfix` 分支，有进行了几次提交

![基于 `master` 分支的紧急问题分支（hotfix branch）。](images/Git.assets/basic-branching-4.png)



将 `hotfix` 分支合并回你的 `master` 分支来部署到线上。这时会使用**快进合并**。于你想要合并的分支 `hotfix` 所指向的提交 `C4` 是你所在的提交 `C2` 的直接后继， 因此Git 会直接将指针向前移动，这种情况下的合并操作没有需要解决的分歧，就会使用快进合并。

![`master` 被快进到 `hotfix`。](images/Git.assets/basic-branching-5.png)



## 三方合并

现在删除了hotfix分支，并且打算将iss53分支，并入 `master` 分支

![继续在 `iss53` 分支上的工作。](images/Git.assets/basic-branching-6.png)



开发历史从一个更早的地方开始分叉开来。 `master` 分支所在提交并不是 `iss53` 分支所在提交的直接祖先。

出现这种情况的时候，Git 会使用两个分支的末端所指的快照（`C4` 和 `C5`）以及这两个分支的公共祖先（`C2`），做一个简单的三方合并。

将iss53分支合并到当前分支

```
git merge iss53
```

![一次典型合并中所用到的三个快照。](images/Git.assets/basic-merging-1.png)





此次三方合并的结果做了一个新的快照并且自动创建一个新的提交指向它。

 这被称作一次合并提交，它的特别之处在于他有不止一个父提交。

![一个合并提交。](images/Git.assets/basic-merging-2.png)



### 一个示例

1. 假设你有一个名为`master`的分支，包含了提交`c1`、`c2`、`c3`和`c4`。
2. 在`master`分支的`c2`提交处，你创建了一个新的分支`iss`。
3. 在`iss`分支上，你进行了两次提交，生成了`c5`和`c6`。



4. 你使用了三方合并（3-way merge），将`iss`分支合并到`master`分支。

5. 这会在`master`分支上创建一个新的合并提交`c7`，它包含了`iss`分支上的`c5`和`c6`提交的所有更改。



6. 当你删除`iss`分支后，`c5`和`c6`提交仍然属于`master`分支，因为它们已经被合并进来了。



7. 在将`iss`分支合并到`master`分支后，`iss`分支仍然会指向`c6`提交。这是因为合并操作不会改变源分支的位置。

希望这个教程能帮到你！



### 合并时遇到冲突

如果两个不同的分支中，对同一个文件的同一个部分进行了不同的修改，Git 就没法干净的合并它们。 

Git 做了合并，但是没有自动地创建一个新的合并提交。 Git 会暂停下来，等待你去解决合并产生的冲突。 

在合并冲突后的任意时刻使用 `git status` 命令来**查看**，**因包含合并冲突**而处于**未合并状态**（unmerged）的文件：



Git 会在有冲突的文件中加入标准的冲突解决标记，这样你可以打开这些包含冲突的文件然后手动解决冲突。 出现冲突的文件会包含一些特殊区段，看起来像下面这个样子：

```html
<<<<<<< HEAD:index.html
<div id="footer">contact : email.support@github.com</div>
=======
<div id="footer">
 please contact us at support@github.com
</div>
>>>>>>> iss53:index.html
```



 `HEAD` 分支所指示的版本，在这个区段的上半部分（`=======` 的上半部分）。

`iss53` 分支所指示的版本，在 `=======` 的下半部分。 

为了解决冲突，必须选择使用由 `=======` 分割的两部分中的一个，或者你也可以自行合并这些内容。





 例如，你可以通过把这段内容换成下面的样子来解决冲突：

```html
<div id="footer">
please contact us at email.support@github.com
</div>
```

上述的冲突解决方案，仅保留了其中一个分支的修改，并且 `<<<<<<<` , `=======` , 和 `>>>>>>>` 这些行被完全删除了。

 在解决了所有文件里的冲突之后，对每个文件使用 `git add` 命令来将其标记为冲突已解决。

 一旦暂存这些原本有冲突的文件，Git 就会将它们标记为冲突已解决。



解决完成所有冲突后，可以使用`git commit` 来完成合并提交。



## 分支管理

`git branch` 命令可以创建与删除分支。 如果不加任何参数运行它，会得到当前所有分支的一个列表：

```console
git branch
  iss53
* master
  testing
```

 `*` 字符：它代表现在检出的那一个分支（也就是说，当前 `HEAD` 指针所指向的分支）



 `git branch -v` 命令，查看每一个分支的最后一次提交

```console
$ git branch -v
  iss53   93b412c fix javascript issue
* master  7a98805 Merge branch 'iss53'
  testing 782fd34 add scott to the author list in the readmes
```



`--merged` 与 `--no-merged` 过滤这个列表中已经合并或尚未合并到当前分支的分支。

查看哪些分支已经合并到当前分支，可以运行 `git branch --merged`：

```console
$ git branch --merged
  iss53
* master
```



`branch -d` 删除掉一个分支

```
git branch -d testing
```



如果它包含了还未合并的工作，尝试使用 `git branch -d` 命令删除它时会失败：

```console
$ git branch -d testing
error: The branch 'testing' is not fully merged.
If you are sure you want to delete it, run 'git branch -D testing'.
```

如果真的想要删除分支并丢掉那些工作，如同帮助信息里所指出的，可以使用 `-D` 选项强制删除它。



# 远程分支

## 远程引用

远程引用指的是对远程仓库的引用（指针），包括分支、标签等等。

 `git ls-remote <remote>` 来显式地获得远程引用的完整列表

 `git remote show <remote>` 获得远程分支的更多信息。 



**远程跟踪分支**就像是你的书签，它帮助你记住远程仓库中的分支在你最后一次更新时的位置。



这些书签的名字通常是这样的：`<远程仓库的名字>/<分支的名字>`。比如 `origin/master` 就代表了你最后一次更新时，远程仓库 `origin` 中的 `master` 分支的位置。



## 跟踪分支

1. **克隆仓库时的跟踪分支**：当你克隆一个仓库时，通常会自动创建一个跟踪 `origin/master` 的 `master` 分支。
2. **创建新的跟踪分支**：你可以使用 `git checkout -b <branch> <remote>/<branch>` 命令创建新的跟踪分支。Git 提供了 `--track` 选项作为快捷方式，例如：`git checkout --track origin/serverfix`。
3. **自动创建跟踪分支**：如果你尝试检出的分支不存在，并且只有一个远程分支的名字与之匹配，那么 Git 会自动为你创建一个跟踪分支，例如：`git checkout serverfix`。
4. **使用不同的名字设置本地分支和远程分支**：你可以使用上述命令轻松地增加一个具有不同名字的本地分支，例如：`git checkout -b sf origin/serverfix`。这样，本地分支 `sf` 就会自动从 `origin/serverfix` 拉取。
5. **设置已有的本地分支跟踪远程分支**：你可以在任何时候使用 `-u` 或 `--set-upstream-to` 选项运行 `git branch` 来显式地设置，例如：`git branch -u origin/serverfix`。



远程仓库名字 “origin” 与分支名字 “master” 一样，在 Git 中并没有任何特别的含义一样。 同时 “master” 是当你运行 `git init` 时默认的起始分支名字，原因仅仅是它的广泛使用， “origin” 是当你运行 `git clone` 时默认的远程仓库名字。 如果你运行 `git clone -o booyah`，那么你默认的远程分支名字将会是 `booyah/master`

​	

![克隆之后的服务器与本地仓库。](images/Git.assets/remote-branches-1.png)



如果你在本地的 `master` 分支做了一些工作，在同一段时间内有其他人推送提交到 `git.ourcompany.com` 并且更新了它的 `master` 分支，这就是说你们的提交历史已走向不同的方向。 即便这样，只要你保持不与 `origin` 服务器连接（并拉取数据），你的 `origin/master` 指针就不会移动。



![本地与远程的工作可以分叉。](images/Git.assets/remote-branches-2.png)



如果要与给定的远程仓库同步数据，运行 `git fetch <remote>` 命令（在本例中为 `git fetch origin`）。 这个命令查找 `origin` 是哪一个服务器（在本例中，它是 `git.ourcompany.com`）， 从中抓取本地没有的数据，并且更新本地数据库，移动 `origin/master` 指针到更新之后的位置。



![`git fetch` 更新你的远程仓库引用。](images/Git.assets/remote-branches-3.png)



## 添加另一个远程仓库

有另一个内部 Git 服务器，位于 `git.team1.ourcompany.com`。已经通过 `git remote add` 命令添加到当前项目。

现在，可以运行 `git fetch teamone` 来抓取远程仓库 `teamone` 有而本地没有的数据。 因为那台服务器上现有的数据是 `origin` 服务器上的一个子集， 所以 Git 并不会抓取数据而是会设置远程跟踪分支 `teamone/master` 指向 `teamone` 的 `master` 分支。

![添加另一个远程仓库。](images/Git.assets/remote-branches-4.png)



## 推送

当你想要公开分享一个分支时，需要将其推送到有写入权限的远程仓库上。 本地的分支并不会自动与远程仓库同步——你必须显式地推送想要分享的分支。 这样，你就可以把不愿意分享的内容放到私人分支上，而将需要和别人协作的内容推送到公开分支。

如果希望和别人一起在名为 `serverfix` 的分支上工作，你可以像推送第一个分支那样推送它。

下一次其他协作者从服务器上抓取数据时，他们会在本地生成一个远程分支 `origin/serverfix`

```
git push <remote> <branch>
```



## 拉取

当 `git fetch` 命令从服务器上抓取本地没有的数据时，它并不会修改工作目录中的内容。 它只会获取数据然后让你自己合并。 然而，有一个命令叫作 `git pull` 在大多数情况下它的含义是一个 `git fetch` 紧接着一个 `git merge` 命令。 如果有一个像之前章节中演示的设置好的跟踪分支，不管它是显式地设置还是通过 `clone` 或 `checkout` 命令为你创建的，`git pull` 都会查找当前分支所跟踪的服务器与分支， 从服务器上抓取数据然后尝试合并入那个远程分支。

由于 `git pull` 的魔法经常令人困惑所以通常单独显式地使用 `fetch` 与 `merge` 命令会更好一些。



# 变基

`rebase` 命令将提交到某一分支上的所有修改都移至另一分支上，就好像“重新播放”一样。"重新播放"在这里的意思是将一系列的修改或操作再次执行一遍

首先找到这两个分支（即**当前分支** `experiment`、变基操作的**目标基底分支** `master`）的**最近共同祖先** `C2`，然后对比**当前分支**相对于该**祖先**的**历次提交**，把**历史提交依序应用**到**新的基底**上，然后将当前分支指向目标基底 `C3`。

 ![将 `C4` 中的修改变基到 `C3` 上。](images/Git.assets/basic-rebase-3.png)

现在回到 `master` 分支，进行一次快进合并。

![`master` 分支的快进合并。](images/Git.assets/basic-rebase-4.png)

## 变基冲突

1. 在master分支进行`c1、c2、c3`提交。
2. 在c1提交创建了`test`分支，后续进行`c4、c5`提交。
3. 将test分支变基到master分支。
4. 当运行 git rebase master 命令时，Git 会尝试将 c4 和 c5 的修改应用到 master 分支上。
5. 如果 c4 的修改与 c2 或 c3 的修改冲突，需要手动解决冲突后通过git add 命令添加到暂存区，然后git rebase --continue 命令继续进行变基操作。
6. 如果 c6 的修改与 c2 或 c3 的修改冲突，你需要再次解决这些冲突。







## 有趣的变基例子

“变基（rebase）” 操作通常用于将一系列的提交从一个分支移动到另一个分支。然而，你也可以选择将这些提交应用到一个完全不同的分支。

你创建了一个主题分支 `server`，为服务端添加了一些功能，提交了 `C3` 和 `C4`。 

然后从 `C3` 上创建了主题分支 `client`，为客户端添加了一些功能，提交了 `C8` 和 `C9`。

 最后，你回到 `server` 分支，又提交了 `C10`。

![从一个主题分支里再分出一个主题分支的提交历史。](images/Git.assets/interesting-rebase-1.png)



假设你希望合并`client`，但暂时不合并`server`。

 `git rebase` 命令的 `--onto` 选项，将**仅存在于`client`分支**（不存在于`server`分支）中的提交（c8、c9），将它们变基到master分支上。（在 `master` 分支上重放）。

```
git rebase --onto master server client
```

![从一个主题分支里再分出一个主题分支的提交历史。](images/Git.assets/interesting-rebase-1-1705229932856-7.png)





快进合并 `master` 分支

```
git checkout master
git merge client
```

![快进合并 `master` 分支，使之包含来自 `client` 分支的修改。](images/Git.assets/interesting-rebase-3.png)



现在将server分支变基到master分支上。

 `git rebase <basebranch> <topicbranch>` 命令可以直接将主题分支 （即本例中的 `server`）变基到目标分支（即 `master`）上。

 这样做能省去你先切换到 `server` 分支，再对其执行变基命令的多个步骤。

```console
git rebase master server
```

![将 `server` 中的修改变基到 `master` 上。](images/Git.assets/interesting-rebase-4.png)



快进合并主分支 `master` 了：

```console
$ git checkout master
$ git merge server
```

`client` 和 `server` 分支的提交已经变基到master分支

删除`client`和`server`分支后的历史提交

![最终的提交历史。](images/Git.assets/interesting-rebase-5.png)



## 变基风险

假设你从一个中央服务器克隆然后在它的基础上进行了一些开发。 你的提交历史如图所示：

![克隆一个仓库，然后在它的基础上进行了一些开发。](images/Git.assets/perils-of-rebasing-1.png)

某人向中央服务器提交了一些修改，其中还包括一次合并。 

你抓取了这些在远程分支上的修改，并将其合并到你本地的开发分支，然后你的提交历史就会变成这样：

![抓取别人的提交，合并到自己的开发分支。](images/Git.assets/perils-of-rebasing-2.png)

这个人决定把合并操作回滚，改用变基；

继而又用 `git push --force` 命令覆盖了服务器上的提交历史。 

你从服务器抓取更新，会发现多出来一些新的提交。

![有人推送了经过变基的提交，并丢弃了你的本地开发所基于的一些提交。](images/Git.assets/perils-of-rebasing-3.png)

如果你合并来自两条提交历史的内容，生成一个新的合并提交，最终仓库会如图所示：

你会发现有两个提交的作者、日期、日志居然是一样的（c4、c4'）。

如果你又推送到服务器上，实际上是将那些已经被变基抛弃的提交又找了回来。

对方**又看到并不想看到**提交历史中的 `C4` 和 `C6`，因为之前就是他把这两个提交通过变基丢弃的。

 ![你将相同的内容又合并了一次，生成了一个新的提交。](images/Git.assets/perils-of-rebasing-4.png)



## 用变基解决变基

如果团队中的某人强制推送并覆盖了一些你所基于的提交，你需要做的就是检查你做了哪些修改，以及他们覆盖了哪些修改。

Git 除了对整个提交计算 SHA-1 校验和以外，也对本次提交所引入的修改计算了校验和。

如果你**拉取被覆盖过的更新**（`teamone/master`）并将你**手头的工作**（`master`）基于此进行变基的话（将`master`变基到`teamone/master`），一般情况下 Git 都能成功分辨出哪些是你的修改，并把它们应用到新分支上。

执行 `git rebase teamone/master`



- 检查哪些提交是**我们的分支上独有**的提交（C2，C3，C4，C6，C7）
- 检查其中哪些提交**不是合并操作**的产生的提交（C2，C3，C4）
- 检查哪些提交**在对方覆盖更新时**并**没有被纳入目标分支**的提交（只有 C2 和 C3，因为 C4 其实就是 C4'）

总结：将**我们分支上独有**且**不是合并操作产生**且**不存在于目标分支**的提交，变基到目标分支上。

![你将相同的内容又合并了一次，生成了一个新的提交。](images/Git.assets/perils-of-rebasing-4-1705231603953-24.png)

执行 `git rebase teamone/master`后的结果

![在一个被变基然后强制推送的分支上再次执行变基。](images/Git.assets/perils-of-rebasing-5.png)

如果在变基操作中，对方在变基时没有确保 C4’ 和 C4 是几乎一样的，那么 Git 在执行变基操作时将无法识别它们是相同的提交。这可能会导致 Git 创建一个新的、类似于 C4 的补丁。然而，这个新的补丁可能无法整洁地整合入历史，因为补丁中的修改已经存在于某个地方了。



## 合并vs变基

1. 提交历史的意义：有两种不同的观点。一种观点认为，提交历史是记录实际发生过什么的文档，本身就有价值，不能乱改。另一种观点认为，提交历史是项目过程中发生的事，可以使用 rebase 和 filter-branch 等工具来编写故事，怎么方便后来的读者就怎么写。

2. 合并 vs 变基：合并和变基都是 Git 中整合分支的方法，但它们的工作方式不同。合并将不同分支的更改合并到一起，形成一个新的提交；变基将一个分支的提交直接应用到另一个分支的末尾，不会产生新的合并提交。合并更适合处理复杂的合并操作和冲突，保留每个分支的完整历史记录；而变基更适合保持一个干净的提交历史记录，使得整个项目更易于理解和追踪。

3. 选择合并还是变基：这并没有一个简单的答案。Git 是一个非常强大的工具，它允许你对提交历史做许多事情，但每个团队、每个项目对此的需求并不相同。既然你已经分别学习了两者的用法，相信你能够根据实际情况作出明智的选择。

4. 变基的原则：只对尚未推送或分享给别人的本地修改执行变基操作清理历史，从不对已推送至别处的提交执行变基操作，这样，你才能享受到两种方式带来的便利。
