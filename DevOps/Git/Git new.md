# Git

## 基础配置

### 初次运行 Git 前的配置

**Git 配置文件路径和优先级**

Git 自带一个 `git config` 的工具来帮助设置控制 Git 外观和行为的配置变量。 这些变量存储在三个不同的位置：

1. `/etc/gitconfig` 文件: 包含系统上每一个用户及他们仓库的通用配置。 如果在执行 `git config` 时带上 `--system` 选项，那么它就会读写该文件中的配置变量。 （由于它是系统配置文件，因此你需要管理员或超级用户权限来修改它。）

2. `~/.gitconfig` 或 `~/.config/git/config` 文件：只针对当前用户。 你可以传递 `--global` 选项让 Git 读写此文件，这会对你系统上**所有**的仓库生效。

3. `.git/config`：当前使用仓库的 Git 目录中的 `config` 文件（仅针对该仓库）。 你可以传递 `--local` 选项让 Git 强制读写此文件，虽然默认情况下用的就是它。

每一个级别会覆盖上一级别的配置，所以 `.git/config` 的配置变量会覆盖 `/etc/gitconfig` 中的配置变量。



通过以下命令查看所有的配置以及它们所在的文件：

```
git config --list --show-origin
```



**用户信息**

安装完 Git 之后，要做的第一件事就是设置你的用户名和邮件地址。 这一点很重要，因为每一个 Git 提交都会使用这些信息，它们会写入到你的每一次提交中，不可更改：

```
git config --global user.name "John Doe"
git config --global user.email johndoe@example.com
```

*再次强调，如果使用了 `--global` 选项，那么该命令只需要运行一次，因为之后无论你在该系统上做任何事情， Git 都会使用那些信息。* 

*当你想针对特定项目使用不同的用户名称与邮件地址时，可以在那个项目目录下运行没有 `--global` 选项的命令来配置。*



**文本编辑器**

当 Git 需要你输入信息时会调用文本编辑器，你可以配置默认文本编辑器。如果未配置，Git 会使用操作系统默认的文本编辑器。



如果你想使用不同的文本编辑器，例如 Emacs，可以这样做：

```
git config --global core.editor vim
```



**检查配置信息**

如果想要检查你的配置，可以使用 `git config --list` 命令来列出所有 Git 当时能找到的配置：

```
$ git config --list
user.name=John Doe
user.email=johndoe@example.com
color.status=auto
color.branch=auto
color.interactive=auto
color.diff=auto
...
```

*你可能会看到重复的变量名，因为 Git 会从不同的文件中读取同一个配置（例如：`/etc/gitconfig` 与 `~/.gitconfig`）。* 

*这种情况下，Git 会使用它找到的每一个变量的最后一个配置。*



你可以通过输入 `git config <key>`： 来检查 Git 的某一项配置：

```
$ git config user.name
John Doe
```



### 获取 Git 仓库

通常有两种获取 Git 项目仓库的方式：

1. **初始化仓库**，将尚未进行版本控制的本地目录转换为 Git 仓库；
2. **克隆仓库**，从其它服务器**克隆**一个已存在的 Git 仓库。



**在已存在目录中<u>初始化仓库</u>**

如果你有一个尚未进行版本控制的项目目录，想要用 Git 来控制它，那么首先需要进入该项目目录中。

```
cd /home/user/my_project
```

之后执行：

```
git init
```

*该命令将创建一个名为 `.git` 的子目录，这个子目录含有你初始化的 Git 仓库中所有的必须文件，这些文件是 Git 仓库的骨干。现在仅仅是做了一个初始化的操作，项目里的文件还没有被跟踪。*



如果在一个已存在文件的文件夹（而非空文件夹）中进行版本控制，你应该开始追踪这些文件并进行初始提交。 可以通过 `git add` 命令来指定所需的文件来进行追踪，然后执行 `git commit` ：

```
git add *.c
git add LICENSE
git commit -m 'initial project version'
```



**克隆现有的仓库**

如果你想获得一份已经存在了的 Git 仓库的拷贝，比如说，你想为某个开源项目贡献自己的一份力，这时就要用到 `git clone` 命令。

当你执行 `git clone` 命令的时候，默认配置下远程 Git 仓库中的每一个文件的每一个版本都将被拉取下来。



克隆仓库的命令是 `git clone <url>` 。 比如，要克隆 Git 的链接库 `libgit2`，可以用下面的命令：

```
git clone https://github.com/libgit2/libgit2
```

*这会在当前目录下创建一个名为 “libgit2” 的目录，并在这个目录下初始化一个 `.git` 文件夹， 从远程仓库拉取下所有数据放入 `.git` 文件夹，然后从中读取最新版本的文件的拷贝。 如果你进入到这个新建的 `libgit2` 文件夹，你会发现所有的项目文件已经在里面了，准备就绪等待后续的开发和使用。*



如果你想在克隆远程仓库的时候，自定义本地仓库的名字，你可以通过额外的参数指定新的目录名：

```
git clone https://github.com/libgit2/libgit2 mylibgit
```

*这会执行与上一条命令相同的操作，但目标目录名变为了 `mylibgit`。*



### 记录每次更新到仓库

现在主机上存在一个**真实项目**的 Git 仓库。

工作目录下的每一个文件都不外乎这两种状态：**已跟踪**或**未跟踪**。 

- **已跟踪**的文件是指那些被**纳入了版本控制的文件**，在上一次快照中有它们的记录，在工作一段时间后， 它们的状态可能是未修改，已修改或已放入暂存区。
- **未跟踪**的文件是指工作目录中**除已跟踪文件外的其它所有文件**，它们既不存在于上次快照的记录中，也没有被放入暂存区。

初次克隆某个仓库的时候，工作目录中的所有文件都属于已跟踪文件，并处于未修改状态，因为 Git 刚刚检出了它们， 而你尚未编辑过它们。



编辑过某些文件之后，由于自上次提交后你对它们做了修改，Git 将它们标记为已修改文件。 在工作时，你可以选择性地将这些修改过的文件放入暂存区，然后提交所有已暂存的修改，如此反复。

![image-20250925102305472](./images/Git%20new.assets/image-20250925102305472.png)



#### 检查当前文件状态

可以用 `git status` 命令查看哪些文件处于什么状态。 如果在克隆仓库后立即使用此命令，会看到类似这样的输出：

```
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
nothing to commit, working directory clean
```

*这说明现在的工作目录相当干净，所有已跟踪文件在上次提交后都未被更改过。*

*当前目录下没有出现任何处于未跟踪状态的新文件，否则 Git 会在这里列出来。* 

*命令显示了当前所在分支，并告诉你这个分支同远程服务器上对应的分支没有偏离。* 

*现在，分支名是“master”，这是默认的分支名。*



在项目下创建一个新的 `README` 文件。 因为之前并不存在这个文件，使用 `git status` 命令，你将看到一个新的未跟踪文件：

```
$ echo 'My Project' > README
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Untracked files:
  (use "git add <file>..." to include in what will be committed)

    README

nothing added to commit but untracked files present (use "git add" to track)
```

*在状态报告中可以看到新建的 `README` 文件出现在 `Untracked files` 下面。 未跟踪的文件意味着 Git 在之前的快照（提交）中没有这些文件；*

*Git 不会自动将之纳入跟踪范围，除非你将文件添加到暂存区。这种处理方式能确保你只追踪需要版本控制的文件，不必担心将编译生成的二进制文件或其他不必要的文件也包括进来。*





#### 跟踪新文件

使用命令 `git add` 开始跟踪一个文件。 所以，要跟踪 `README` 文件，运行：

```
git add README
```



此时再运行 `git status` 命令，会看到 `README` 文件已被跟踪，并处于暂存状态：

```
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)

    new file:   README
```

*只要在 `Changes to be committed` 这行下面的，就说明是已暂存状态。如果此时提交，那么该文件在你运行 `git add` 时的版本将被留存在后续的历史记录中。*

*`git add` 命令使用文件或目录的路径作为参数；如果参数是目录的路径，该命令将递归地跟踪该目录下的所有文件。*





#### 暂存已修改的文件

现在我们来修改一个已被跟踪的文件。 如果你修改了一个名为 `CONTRIBUTING.md` 的已被跟踪的文件，然后运行 `git status` 命令，会看到下面内容：

```
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

*文件 `CONTRIBUTING.md` 出现在 `Changes not staged for commit` 这行下面，说明已跟踪文件的内容发生了变化，但还没有放到暂存区。*

*要暂存这次更新，需要运行 `git add` 命令。 这是个多功能命令：可以用它开始跟踪新文件，或者把已跟踪的文件放到暂存区，还能用于合并时把有冲突的文件标记为已解决状态等。*

*将这个命令理解为“**精确地将内容添加到下一次提交中**”而不是“将一个文件添加到项目中”要更加合适。*



现在让我们运行 `git add` 将“CONTRIBUTING.md”放到暂存区，然后再看看 `git status` 的输出：

```
$ git add CONTRIBUTING.md
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    new file:   README
    modified:   CONTRIBUTING.md
```



现在两个文件都已暂存，下次提交时就会一并记录到仓库。 假设此时，你想要在 `CONTRIBUTING.md` 里再加条注释。重新编辑存盘后，再运行 `git status` 看看：

```
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

现在 `CONTRIBUTING.md` 文件同时出现在暂存区和非暂存区。

Git 仅暂存了你运行 `git add` 命令时的版本。 如果你现在提交，`CONTRIBUTING.md` 的版本是你最后一次运行 `git add` 命令时的那个版本，而不是你运行 `git commit` 时，在工作目录中的当前版本。



如果你对文件进行了修改，并且希望提交这些最新修改，需要重新运行 `git add` 把最新版本重新暂存起来：

```
$ git add CONTRIBUTING.md
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    new file:   README
    modified:   CONTRIBUTING.md
```





#### 状态简览

`git status` 命令的输出十分详细，但其用语有些繁琐。Git 有一个选项可以帮你缩短状态命令的输出，这样可以以简洁的方式查看更改。

如果你使用 `git status -s` 命令或 `git status --short` 命令，你将得到一种格式更为紧凑的输出。

```
$ git status -s
 M README
MM Rakefile
A  lib/git.rb
M  lib/simplegit.rb
?? LICENSE.txt
```

`??` 标记：文件是**未被 Git 追踪**的。文件存在于你的工作目录中，但它还没有被添加到你的 Git 仓库中。

`A` 标记：文件是**新增并已暂存**的。创建了一个新文件，并使用 `git add` 命令将它添加到了暂存区。

`red M` 标记：文件在修改后未添加到暂存区。

`green M` 标记：文件在**暂存区**中处于已修改状态。这意味着你在上次提交后，对文件进行了修改，并运行了 `git add` 命令将其添加到暂存区。

`MM` 标记：文件在**工作目录**中处于已修改状态。这意味着你在运行 `git add` 后又对这个文件做了新的改动，但还没有将这些最新改动暂存起来。

`D` 标记：文件已被**删除**，并且这个删除操作已经暂存。

`R` 标记：文件已被**重命名**。Git 能够检测到文件的重命名操作，并将其作为一次原子性更改进行跟踪。

`C` 标记：文件已被**复制**。这类似于重命名，Git 能够识别出新文件是从旧文件复制而来。

`U` 标记：文件处于**未合并**状态。当你在合并分支时发生冲突，并且你还没有解决这些冲突时，就会出现这个标记。





#### 忽略文件

有些文件无需纳入 Git 的管理，也不希望它们总出现在未跟踪文件列表。通常都是些自动生成的文件，比如日志文件，或者编译过程中创建的临时文件等。



在这种情况下，我们可以创建一个名为 `.gitignore` 的文件，列出要忽略的文件的模式。 来看一个实际的 `.gitignore` 例子：

```
$ cat .gitignore
*.[oa]
*~
```

*第一行告诉 Git 忽略所有以 `.o` 或 `.a` 结尾的文件。一般这类对象文件和存档文件都是编译过程中出现的。*

*第二行告诉 Git 忽略所有名字以波浪符（~）结尾的文件，许多文本编辑软件（比如 Emacs）都用这样的文件名保存副本。*

*此外，你可能还需要忽略 log，tmp 或者 pid 目录，以及自动生成的文档等等。 要养成一开始就为你的新仓库设置好 .gitignore 文件的习惯，以免将来误提交这类无用的文件。*



**此处仅介绍有 Git 工具存在忽略工具的功能，具体语法暂不介绍。**





#### 查看已暂存和未暂存的修改

`git diff` 能通过文件补丁的格式更加具体地显示哪些行发生了改变。

`git diff` 会比较你的工作目录和暂存区之间的差异。但要注意，这个命令只会显示那些已经被 Git 追踪（tracked）的文件所做的修改。如果文件是新增的并且还没有被 `git add` 暂存，`git diff` 是不会显示它们的。如果一个已经被追踪的文件被修改了但还没有暂存，那么 `git diff` 实际上会显示这个文件的**工作目录**版本和它在**暂存区**版本之间的差异。



假如修改 README 文件后暂存，然后编辑 `CONTRIBUTING.md` 文件后先不暂存， 运行 `status` 命令将会看到：

```
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    modified:   README

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

    modified:   CONTRIBUTING.md
```



要查看尚未暂存的文件更新了哪些部分，不加参数直接输入 `git diff`：

```
$ git diff
diff --git a/CONTRIBUTING.md b/CONTRIBUTING.md
index 8ebb991..643e24f 100644
--- a/CONTRIBUTING.md
+++ b/CONTRIBUTING.md
@@ -65,7 +65,8 @@ branch directly, things can get messy.
 Please include a nice description of your changes when you submit your PR;
 if we have to read the whole diff to figure out why you're contributing
 in the first place, you're less likely to get feedback and have your change
-merged in.
+merged in. Also, split your changes into comprehensive chunks if your patch is
+longer than a dozen lines.

 If you are starting to work on a particular area, feel free to submit a PR
 that highlights your work in progress (and note in the PR title that it's
```



若要查看**已暂存文件**与**最后一次提交**的文件差异，可以用 `git diff --staged` 命令。

```
$ git diff --staged
diff --git a/README b/README
new file mode 100644
index 0000000..03902a1
--- /dev/null
+++ b/README
@@ -0,0 +1 @@
+My Project
```

*请注意，git diff 本身只显示**尚未暂存的改动**，而不是自上次提交以来所做的所有改动。 所以有时候你一下子暂存了所有更新过的文件，运行 `git diff` 后却什么也没有，就是这个原因。*





#### 提交更新

现在的暂存区已经准备就绪，可以提交了。 在此之前，请务必确认还有什么已修改或新建的文件还没有 `git add` 过， 否则提交的时候不会记录这些尚未暂存的变化。 

这些已修改但未暂存的文件只会保留在本地磁盘。 所以，每次准备提交前，先用 `git status` 看下，你所需要的文件是不是都已暂存起来了， 然后再运行提交命令 `git commit`：

```
$ git commit
```



这样会启动你选择的文本编辑器来输入提交说明。

编辑器会显示类似下面的文本信息（本例选用 Vim 的屏显方式展示）：

```
# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
# On branch master
# Your branch is up-to-date with 'origin/master'.
#
# Changes to be committed:
#	new file:   README
#	modified:   CONTRIBUTING.md
#
~
~
~
".git/COMMIT_EDITMSG" 9L, 283C
```

*可以看到，默认的提交消息包含最后一次运行 `git status` 的输出，放在注释行里，另外开头还有一个空行，供你输入提交说明。* 

*你完全可以去掉这些注释行，不过留着也没关系，多少能帮你回想起这次更新的内容有哪些。*

*退出编辑器时*，Git 会丢弃注释行，用你输入的提交说明生成一次提交。



另外，你也可以在 `commit` 命令后添加 `-m` 选项，将提交信息与命令放在同一行，如下所示：

```
$ git commit -m "Story 182: Fix benchmarks for speed"
[master 463dc4f] Story 182: Fix benchmarks for speed
 2 files changed, 2 insertions(+)
 create mode 100644 README
```

现在已经创建了第一个提交！ 提交后会显示，当前是在哪个分支（`master`）提交的，本次提交的完整 SHA-1 校验和是什么（`463dc4f`），以及在本次提交中，有多少文件修订过，多少行添加和删改过。





#### 跳过使用暂存区域

Git 提供了一个跳过使用暂存区域的方式， 只要在提交的时候，给 `git commit` 加上 `-a` 选项，Git 就会自动把所有已经跟踪过的文件暂存起来一并提交，从而跳过 `git add` 步骤：

```
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

    modified:   CONTRIBUTING.md

no changes added to commit (use "git add" and/or "git commit -a")
$ git commit -a -m 'added new benchmarks'
[master 83e38c7] added new benchmarks
 1 file changed, 5 insertions(+), 0 deletions(-)
```

***注意：Git 仅会提交已跟踪的文件，Git 不会自动提交新增的文件。***





#### 移除文件

 `git rm` 命令用于从工作目录中删除指定的文件，并将删除文件这一操作添加到暂存区中。



如果只是简单地从工作目录中手工删除文件，运行 `git status` 时就会在 “Changes not staged for commit” 部分（也就是 *未暂存清单*）看到：

```
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

```
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



如果要删除之前修改过或已经放到暂存区的文件，则必须使用强制删除选项 `-f`（译注：即 force 的首字母）。 这是一种安全特性，用于防止误删尚未添加到快照的数据，这样的数据不能被 Git 恢复。



另外一种情况是把文件从 Git 暂存区域移除，但仍然希望保留在当前工作目录中。为达到这一目的，使用 `--cached` 选项：

```
$ git rm --cached README
```

*当你忘记添加 `.gitignore` 文件，不小心把一个很大的日志文件或一堆 `.a` 这样的编译生成文件添加到暂存区时，这一做法尤其有用。*





#### 移动文件

`git mv` 命令用于对工作目录中的文件进行重命名或移动位置。



要在 Git 中对文件改名，可以这么做：

```
$ git mv file_from file_to
```



它会恰如预期般正常工作。 实际上，即便此时查看状态信息，也会明白无误地看到关于重命名操作的说明：

```
$ git mv README.md README
$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    renamed:    README.md -> README
```



其实，运行 `git mv` 就相当于运行了下面三条命令：

```
$ mv README.md README
$ git rm README.md
$ git add README
```

如此分开操作，Git 也会意识到这是一次重命名，所以不管何种方式结果都一样。 两者唯一的区别在于，`git mv` 是一条命令而非三条命令，直接使用 `git mv` 方便得多。 不过在使用其他工具重命名文件时，记得在提交前 `git rm` 删除旧文件名，再 `git add` 添加新文件名。



### 查看提交历史

在提交了若干更新，又或者克隆了某个项目之后，你也许想回顾下提交历史。 完成这个任务最简单而又有效的工具是 `git log` 命令。

`git log` 有许多选项可以帮助你搜寻你所要找的提交， 下面我们会介绍几个最常用的选项。



我们使用一个非常简单的 "simplegit" 项目作为示例。 运行下面的命令获取该项目：

```
$ git clone https://github.com/schacon/simplegit-progit
```



当你在此项目中运行 `git log` 命令时，可以看到下面的输出：

```
$ git log
commit ca82a6dff817ec66f44342007202690a93763949
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Mon Mar 17 21:52:11 2008 -0700

    changed the version number

commit 085bb3bcb608e1e8451d4b2432f8ecbe6306e7e7
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Sat Mar 15 16:40:33 2008 -0700

    removed unnecessary test

commit a11bef06a3f659402fe7563abf99ad00de2209e6
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Sat Mar 15 10:31:28 2008 -0700

    first commit
```

*不传入任何参数的默认情况下，`git log` 会按时间先后顺序列出所有的提交，最近的更新排在最上面。 正如你所看到的，这个命令会列出每个提交的 SHA-1 校验和、作者的名字和电子邮件地址、提交时间以及提交说明。*



#### 比较提交差异

`-p` 或 `--patch` ，它会显示每次提交所引入的差异（按 **补丁** 的格式输出）。 

你也可以限制显示的日志条目数量，例如使用 `-2` 选项来只显示最近的两次提交：

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

*该选项除了显示基本信息之外，还附带了每次提交的变化。 当进行代码审查，或者快速浏览某个搭档的提交所带来的变化的时候，这个参数就非常有用了。*



#### 统计信息

`--stat` 选项，查看每次提交的简略统计信息。

```
$ git log --stat
commit ca82a6dff817ec66f44342007202690a93763949
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Mon Mar 17 21:52:11 2008 -0700

    changed the version number

 Rakefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

commit 085bb3bcb608e1e8451d4b2432f8ecbe6306e7e7
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Sat Mar 15 16:40:33 2008 -0700

    removed unnecessary test

 lib/simplegit.rb | 5 -----
 1 file changed, 5 deletions(-)

commit a11bef06a3f659402fe7563abf99ad00de2209e6
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Sat Mar 15 10:31:28 2008 -0700

    first commit

 README           |  6 ++++++
 Rakefile         | 23 +++++++++++++++++++++++
 lib/simplegit.rb | 25 +++++++++++++++++++++++++
 3 files changed, 54 insertions(+)
```

*`--stat` 选项在每次提交的下面列出所有被修改过的文件、有多少文件被修改了以及被修改过的文件的哪些行被移除或是添加了。 在每次提交的最后还有一个总结。*







#### 展示格式

`--pretty` 选项可以使用不同于默认格式的方式展示提交历史。选项可以使用不同于默认格式的方式展示提交历史。

`oneline` 会将每个提交放在一行显示，在浏览大量的提交时非常有用。 另外还有 `short`，`full` 和 `fuller` 选项，它们展示信息的格式基本一致，但是详尽程度不一：

```
$ git log --pretty=oneline
ca82a6dff817ec66f44342007202690a93763949 changed the version number
085bb3bcb608e1e8451d4b2432f8ecbe6306e7e7 removed unnecessary test
a11bef06a3f659402fe7563abf99ad00de2209e6 first commit
```



最有意思的是 `format` ，可以定制记录的显示格式。 这样的输出对后期提取分析格外有用——因为你知道输出的格式不会随着 Git 的更新而发生改变：

```
$ git log --pretty=format:"%h - %an, %ar : %s"
ca82a6d - Scott Chacon, 6 years ago : changed the version number
085bb3b - Scott Chacon, 6 years ago : removed unnecessary test
a11bef0 - Scott Chacon, 6 years ago : first commit
```



`git log --pretty=format` 常用的选项

| 选项  | 说明                                          |
| ----- | --------------------------------------------- |
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

作者指的是实际作出修改的人，提交者指的是最后将此工作成果提交到仓库的人。



当 `oneline` 或 `format` 与另一个 `log` 选项 `--graph` 结合使用时尤其有用。 这个选项添加了一些 ASCII 字符串来形象地展示你的分支、合并历史：

```
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



`git log` 的常用选项

| 选项              | 说明                                                         |
| ----------------- | ------------------------------------------------------------ |
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



#### 限制输出长度

限制 `git log` 输出的选项

| 选项                  | 说明                                       |
| --------------------- | ------------------------------------------ |
| `-<n>`                | 仅显示最近的 n 条提交。                    |
| `--since`, `--after`  | 仅显示指定时间之后的提交。                 |
| `--until`, `--before` | 仅显示指定时间之前的提交。                 |
| `--author`            | 仅显示作者匹配指定字符串的提交。           |
| `--committer`         | 仅显示提交者匹配指定字符串的提交。         |
| `--grep`              | 仅显示提交说明中包含指定字符串的提交。     |
| `-S`                  | 仅显示添加或删除内容匹配指定字符串的提交。 |



##### 提交数量

`git` 可以使用类似 `-<n>` 的选项，其中的 `n` 可以是任何整数，表示仅显示最近的 `n` 条提交。

```
$ git log -2
```



##### 时间范围

`git` 可以通过 `--since` 和 `--until` 参数指定提交记录的时间范围。

- `--since` (或 `--after`)：显示指定时间点 **之后** 的所有提交。
- `--until` (或 `--before`)：显示指定时间点 **之前** 的所有提交。

这两个参数可以单独使用，也可以组合使用来定义一个精确的时间段。



支持多种格式来指定日期：

- **绝对日期**：`YYYY-MM-DD`，例如 `"2025-09-25"`。
- **相对日期**：`"1.day.ago"`、`"2.weeks.ago"`、`"3.months.ago"`。
- **具体时间**：`"2025-09-25 10:00:00"`。



查看最近两周的所有提交（某个时间点到现在的提交）：

```
git log --since="2.weeks.ago"
```



查看 2025 年之前的所有提交（查看某个时间点之前的所有提交）：

```
git log --until="2025-01-01"
```



查找 9 月份的所有提交（某个时间范围的提交）：

```
git log --since="2025-09-01" --until="2025-09-30"
```



查找上周一到上周五的所有提交：

```
git log --since="last monday" --until="last friday"
```



##### 文件内容过滤

`-S`（俗称“pickaxe”选项，取“用鹤嘴锄在土里捡石头”之意）参数，它接受一个字符串参数，并且只会显示那些添加或删除了该字符串的提交。

假设你想找出添加或删除了对某一个特定函数的引用的提交，可以调用：

```
$ git log -S function_name
```



##### 特定文件或路径

`git log` 路径（path）选项，仅查找某些文件或者目录的历史提交，可以在 git log 选项的最后指定它们的路径。 因为是放在最后位置上的选项，所以用两个短划线（--）隔开之前的选项和后面限定的路径名。

```
git log --stat -- aaaa
commit 2212f01b825b87f6d594fd3a6e6f74f38b764555
Author: xiaoshae <xiaoshae@gmail.com>
Date:   Thu Sep 25 12:37:24 2025 +0800

    aaa

 aaaa | 1 -
 1 file changed, 1 deletion(-)

commit aeac3347c5f8024246f3572bd8eb91e7e339f20d
Author: xiaoshae <xiaoshae@gmail.com>
Date:   Thu Sep 25 12:35:29 2025 +0800

    aaa

 aaaa | 1 +
 1 file changed, 1 insertion(+)
```



##### 提交作者

`--author` 选项显示指定作者的提交： 

```
$ git log --author xiaoshae
commit 2d190fa771f7ba07bc755333705fcf6f31e634c0 (HEAD -> master)
Author: xiaoshae <xiaoshae@gmail.com>
Date:   Thu Sep 25 12:38:48 2025 +0800

    aaa

commit 2dd3e32efa410455a3e3a772e3e364315505f2f1
Author: xiaoshae <xiaoshae@gmail.com>
Date:   Thu Sep 25 12:38:25 2025 +0800

    aaa
```



##### 提交说明过滤

`--grep` 选项搜索提交说明中的关键字：

```
$ git log --grep test
commit d3f7c15afe32b0351b80bd9f235f9912f33a5f31
Author: xiaoshae <xiaoshae@gmail.com>
Date:   Thu Sep 25 12:35:03 2025 +0800

    test

commit b411c6eb7545a690aa7f56ff39b4315ecf0fe09f
Author: xiaoshae <xiaoshae@gmail.com>
Date:   Thu Sep 25 12:32:43 2025 +0800

    test
```



在 Git 源码库中查看 Junio Hamano 在 2008 年 10 月其间， 除了合并提交之外的哪一个提交修改了测试文件，可以使用下面的命令：

```
$ git log --pretty="%h - %s" --author='Junio C Hamano' --since="2008-10-01" \
   --before="2008-11-01" --no-merges -- t/
5610e3b - Fix testcase failure when extended attributes are in use
acd3b9e - Enhance hold_lock_file_for_{update,append}() API
f563754 - demonstrate breakage of detached checkout with symbolic link HEAD
d1a43f2 - reset --hard/read-tree --reset -u: remove unmerged new paths
51a94af - Fix "checkout --track -b newbranch" on detached HEAD
b0ad11e - pull: allow "git pull origin $something:$current_branch" into an unborn branch
```

*在近 40000 条提交中，上面的输出仅列出了符合条件的 6 条记录。*



### 撤消操作

在任何一个阶段，你都有可能想要撤消某些操作。 这里，我们将会学习几个撤消你所做修改的基本工具。 注意，有些撤消操作是不可逆的。 这是在使用 Git 的过程中，会因为操作失误而导致之前的工作丢失的少有的几个地方之一。



#### 重新提交

有时候我们提交完了才发现漏掉了几个文件没有添加，或者提交信息写错了。 此时，可以运行带有 `--amend` 选项的提交命令来重新提交：

```
$ git commit --amend
```

*这个命令会将暂存区中的文件提交。 如果自上次提交以来你还未做任何修改（例如，在上次提交后马上执行了此命令）， 那么快照会保持不变，而你所修改的只是提交信息。*

文本编辑器启动后，可以看到之前的提交信息。 编辑后保存会覆盖原来的提交信息。



**简单示例**

例如，你提交后发现提交信息出现了错误，需要求改，可以想下面这样操作：

```
$ git commit -m "add test functoin"
$ git commit --amend -m "add test function"
```



例如，你提交后发现忘记了暂存某些需要的修改，可以像下面这样操作：

```
$ git commit -m 'initial commit'
$ git add forgotten_file
$ git commit --amend
```

*最终你只会有一个提交——第二次提交将代替第一次提交的结果。*



#### 取消暂存的文件

例如，你已经修改了两个文件并且想要将它们作为两次独立的修改提交， 但是却意外地输入 `git add *` 暂存了它们两个，可以使用使用 `git reset HEAD <file>…` 来取消暂存：

```
$ git add *
$ git status
On branch master
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    renamed:    README.md -> README
    modified:   CONTRIBUTING.md


$ git reset HEAD CONTRIBUTING.md
Unstaged changes after reset:
M	CONTRIBUTING.md


$ git status
On branch master
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    renamed:    README.md -> README

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

    modified:   CONTRIBUTING.md
```

*这个命令有点儿奇怪，但是起作用了。 `CONTRIBUTING.md` 文件已经是修改未暂存的状态了。*

*到目前为止这个神奇的调用就是你需要对 `git reset` 命令了解的全部。*

***`git reset` 确实是个危险的命令，如果加上了 `--hard` 选项则更是如此。***



#### 撤消对文件的修改

如果不想保留对 `CONTRIBUTING.md` 文件的修改，可以使用 `git checkout -- <file>...` 放弃工作目录中的更改，将它还原成上次提交时的样子（或者刚克隆完的样子，或者刚把它放入工作目录时的样子）。



在最后一个例子中，未暂存区域是这样：

```
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

    modified:   CONTRIBUTING.md
```



撤销对 **CONTRIBUTING.md** 文件的修改：

```
$ git checkout -- CONTRIBUTING.md
$ git status
On branch master
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

    renamed:    README.md -> README
```

*请务必记得 `git checkout — <file>` 是一个危险的命令。 **你对那个文件在本地的任何修改都会消失**——Git 会用最近提交的版本覆盖掉它。* 

*除非你确实清楚不想要对那个文件的本地修改了，否则请不要使用这个命令。*

*如果你仍然想保留对那个文件做出的修改，但是现在仍然需要撤消，请使用**保存进度与分支**，这通常是更好的做法。*



记住，在 Git 中任何**已提交**的东西几乎总是可以恢复的。 甚至那些被删除的分支中的提交或使用 `--amend` 选项覆盖的提交也可以恢复。

然而，任何你未提交的东西丢失后很可能再也找不到了。



### 远程仓库

远程仓库是指托管在因特网或其他网络中的你的项目的版本库。 你可以有好几个远程仓库，通常有些仓库对你只读，有些则可以读写。 与他人协作涉及管理远程仓库以及根据需要推送或拉取数据。 管理远程仓库包括了解如何添加远程仓库、移除无效的远程仓库、管理不同的远程分支并定义它们是否被跟踪等等。



#### 查看远程仓库

如果想查看你已经配置的远程仓库服务器，可以运行 `git remote` 命令。 它会列出你指定的每一个远程服务器的简写。

如果你已经克隆了自己的仓库，那么至少应该能看到 origin ——这是 Git 给你克隆的仓库服务器的默认名字：

```
$ git clone https://github.com/schacon/ticgit
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



使用选项 `-v`，会显示需要读写远程仓库使用的 Git 保存的简写与其对应的 URL。

```
$ git remote -v
origin	https://github.com/schacon/ticgit (fetch)
origin	https://github.com/schacon/ticgit (push)
```



如果你的远程仓库不止一个，该命令会将它们全部列出。 例如，与几个协作者合作的，拥有多个远程仓库的仓库看起来像下面这样：

```
$ cd grit
$ git remote -v
bakkdoor  https://github.com/bakkdoor/grit (fetch)
bakkdoor  https://github.com/bakkdoor/grit (push)
cho45     https://github.com/cho45/grit (fetch)
cho45     https://github.com/cho45/grit (push)
defunkt   https://github.com/defunkt/grit (fetch)
defunkt   https://github.com/defunkt/grit (push)
koke      git://github.com/koke/grit.git (fetch)
koke      git://github.com/koke/grit.git (push)
origin    git@github.com:mojombo/grit.git (fetch)
origin    git@github.com:mojombo/grit.git (push)
```



#### 跟踪分支

**跟踪分支**（tracking branch）是本地分支，它是指本地分支与一个远程分支建立了直接的连接。这个连接让 Git 知道本地分支“跟踪”哪个远程分支。

当你在这个分支下运行 `git pull` 或 `git push` 等命令时，Git 会自动知道要从哪个远程分支获取更新或推送到哪个远程分支，而不需要你手动指定。

例如，当你运行 `git clone` 克隆一个远程仓库时，Git 会自动创建一个名为 `main`（或 `master`）的本地分支，并将其设置为跟踪远程仓库的 `origin/main`（或 `origin/master`）分支。



`git branch` 命令用于手动将本地分支关联到特定的远程分支。

将本地分支 **master** 手动关联到远程分支 **github/master**（确保你在 `master` 分支上）

```
git branch --set-upstream-to=github/master
```



如果你想创建新分支并立即设置其跟踪远程分支，可以使用 `git checkout -b` 命令：

```
git checkout -b <本地分支名> github/master
```

这个命令会创建一个新的本地分支，并自动将其设置为跟踪 `github/master` 远程分支。





#### 添加远程仓库

`git remote add <shortname> <url>` 添加一个新的远程 Git 仓库，同时指定一个方便使用的简写：

```
$ git remote
origin

$ git remote add pb https://github.com/paulboone/ticgit

$ git remote -v
origin	https://github.com/schacon/ticgit (fetch)
origin	https://github.com/schacon/ticgit (push)
pb	https://github.com/paulboone/ticgit (fetch)
pb	https://github.com/paulboone/ticgit (push)
```

*现在你可以在命令行中使用字符串 `pb` 来代替整个 URL。*



如果你想拉取 Paul 的仓库中有但你没有的信息，可以运行 `git fetch pb`：

```
$ git fetch pb
remote: Counting objects: 43, done.
remote: Compressing objects: 100% (36/36), done.
remote: Total 43 (delta 10), reused 31 (delta 5)
Unpacking objects: 100% (43/43), done.
From https://github.com/paulboone/ticgit
 * [new branch]      master     -> pb/master
 * [new branch]      ticgit     -> pb/ticgit
```

*现在 Paul 的 master 分支可以在本地通过 `pb/master` 访问到——你可以将它合并到自己的某个分支中， 或者如果你想要查看它的话，可以检出一个指向该点的本地分支。*



#### 从远程仓库中抓取与拉取

从远程仓库中获得数据，可以执行：

```
$ git fetch <remote>
```

这个命令会访问远程仓库，从中拉取所有你还没有的数据。 执行完成后，你将会拥有那个远程仓库中所有分支的引用，可以随时合并或查看。

`git fetch` 命令只会将数据下载到你的本地仓库——它并不会自动合并或修改你当前的工作。 当准备好时你必须手动将其合并入你的工作。

如果你的当前分支设置了跟踪远程分支，那么可以用 `git pull` 命令来自动抓取后合并该远程分支到当前分支。



#### 推送到远程仓库

`git push <remote> <branch>` 命令用于将本地分支推送到上游，运行一下命令将 `master` 分支推送到 `origin` 服务器时：

```
$ git push origin master
```

只有当你有所克隆服务器的写入权限，并且之前没有人推送过时，这条命令才能生效。

如果在你克隆仓库之后，有其他人向同一分支推送了新的提交，那么当你尝试推送自己的修改时，你的推送就会因为提交历史不一致而被拒绝。你必须先抓取他们的工作并将其合并进你的工作后才能推送。



#### 查看某个远程仓库

`git remote show <remote>` 命令用于更加详细的查看某一个远程仓库的信息。

```
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



如果你是 Git 的重度使用者，那么还可以通过 `git remote show` 看到更多的信息。

```
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



#### 远程仓库的重命名与移除

`git remote rename` 来修改一个远程仓库的简写名。



例如，想要将 `pb` 重命名为 `paul`，可以用 `git remote rename` 这样做：

```
$ git remote rename pb paul
$ git remote
origin
paul
```

值得注意的是这同样也会修改你所有远程跟踪的分支名字。 那些过去引用 `pb/master` 的现在会引用 `paul/master`。



如果因为一些原因想要移除一个远程仓库——你已经从服务器上搬走了或不再想使用某一个特定的镜像了， 又或者某一个贡献者不再贡献了——可以使用 `git remote remove` 或 `git remote rm` ：

```
$ git remote remove paul
$ git remote
origin
```

一旦你使用这种方式删除了一个远程仓库，那么所有和这个远程仓库相关的远程跟踪分支以及配置信息也会一起被删除。



### 打标签

Git 可以给仓库历史中的某一个提交打上标签，以示重要。 比较有代表性的是人们会使用这个功能来标记发布结点（ `v1.0` 、 `v2.0` 等等）。



#### 列出标签

`git tag` （可带上可选的 `-l` 选项 `--list`）命令用于列出已有的标签：

```
$ git tag
v1.0
v2.0
```

这个命令以字母顺序列出标签，但是它们显示的顺序并不重要。



你也可以按照特定的模式查找标签。 例如，Git 自身的源代码仓库包含标签的数量超过 500 个。 如果只对 1.8.5 系列感兴趣，可以运行：

```
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

*按照通配符列出标签需要 `-l` 或 `--list` 选项。*

*如果你只想要完整的标签列表，那么运行 `git tag` 就会默认假定你想要一个列表，它会直接给你列出来， 此时的 `-l` 或 `--list` 是可选的。*

*然而，如果你提供了一个匹配标签名的通配模式，那么 `-l` 或 `--list` 就是强制使用的。*



#### 创建标签

Git 支持两种标签：轻量标签（lightweight）与附注标签（annotated）。

轻量标签很像一个不会改变的分支——它只是某个特定提交的引用。

附注标签是存储在 Git 数据库中的一个完整对象， 它们是可以被校验的，其中包含打标签者的名字、电子邮件地址、日期时间， 此外还有一个标签信息，并且可以使用 GNU Privacy Guard （GPG）签名并验证。

通常会建议创建附注标签，这样你可以拥有以上所有信息。但是如果你只是想用一个临时的标签， 或者因为某些原因不想要保存这些信息，那么也可以用轻量标签。



#### 附注标签

在 Git 中创建附注标签十分简单。 最简单的方式是当你在运行 `tag` 命令时指定 `-a` 选项：

```
$ git tag -a v1.4 -m "my version 1.4"
$ git tag
v0.1
v1.3
v1.4
```

`-m` 选项指定了一条将会存储在标签中的信息。 如果没有为附注标签指定一条信息，Git 会启动编辑器要求你输入信息。

**无论是轻量标签还是附注标签，标签仅会指向最近的一次提交 (HEAD)。**



通过使用 `git show` 命令可以看到标签信息和与之对应的提交信息：

```
$ git show v1.4
tag v1.4
Tagger: Ben Straub <ben@straub.cc>
Date:   Sat May 3 20:19:12 2014 -0700

my version 1.4

commit ca82a6dff817ec66f44342007202690a93763949
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Mon Mar 17 21:52:11 2008 -0700

    changed the version number
```

*输出显示了打标签者的信息、打标签的日期时间、附注信息，然后显示具体的提交信息。*



#### 轻量标签

轻量标签本质上是将提交校验和存储到一个文件中——没有保存任何其他信息。 创建轻量标签，不需要使用 `-a`、`-s` 或 `-m` 选项，只需要提供标签名字：

```
$ git tag v1.4-lw
$ git tag
v0.1
v1.3
v1.4
v1.4-lw
v1.5
```



这时，如果在标签上运行 `git show`，你不会看到额外的标签信息。 命令只会显示出提交信息：

```console
$ git show v1.4-lw
commit ca82a6dff817ec66f44342007202690a93763949
Author: Scott Chacon <schacon@gee-mail.com>
Date:   Mon Mar 17 21:52:11 2008 -0700

    changed the version number
```



#### 后期打标签

你也可以对过去的提交打标签。 假设提交历史是这样的：

```console
$ git log --pretty=oneline
15027957951b64cf874c3557a0f3547bd83b3ff6 Merge branch 'experiment'
a6b4c97498bd301d84096da251c98a07c7723e65 beginning write support
0d52aaab4479697da7686c15f77a3d64d9165190 one more thing
6d52a271eda8725415634dd79daabbc4d9b6008e Merge branch 'experiment'
0b7434d86859cc7b8c3d5e1dddfed66ff742fcbc added a commit function
4682c3261057305bdd616e23b64b0857d832627b added a todo file
166ae0c4d3f420721acbb115cc33848dfcc2121a started write support
9fceb02d0ae598e95dc970b74767f19372d61af8 updated rakefile
964f16d36dfccde844893cac5b347e7b3d44abbc commit the todo
8a5cbc430f1a9c3d00faaeffd07798508422908a updated readme
```



现在，假设在 v1.2 时你忘记给项目打标签，也就是在 “updated rakefile” 提交。 你可以在之后补上标签。 要在那个提交上打标签，你需要在命令的末尾指定提交的校验和（或部分校验和）：

```
# git tag [标签名] [提交哈希值]
$ git tag -a v1.2 9fceb02
```

***此处为轻量标签***



可以看到你已经在那次提交上打上标签了：

```
$ git tag
v0.1
v1.2
v1.3
v1.4
v1.4-lw
v1.5

$ git show v1.2
tag v1.2
Tagger: Scott Chacon <schacon@gee-mail.com>
Date:   Mon Feb 9 15:32:16 2009 -0800

version 1.2
commit 9fceb02d0ae598e95dc970b74767f19372d61af8
Author: Magnus Chacon <mchacon@gee-mail.com>
Date:   Sun Apr 27 20:43:35 2008 -0700

    updated rakefile
...
```



后期打**附注标签**示例：

```
# git tag -a [标签名] [提交哈希值] -m "[标签信息]" 打标签
$ git tag -a v1.0.0 2a1d3f9 -m "正式发布 v1.0.0 版本"
```



#### 共享标签

默认情况下，`git push` 命令并不会传送标签到远程仓库服务器上。 在创建完标签后你必须显式地推送标签到共享服务器上。



这个过程就像共享远程分支一样——你可以运行 `git push origin <tagname>`。

```
$ git push origin v1.5
Counting objects: 14, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (12/12), done.
Writing objects: 100% (14/14), 2.05 KiB | 0 bytes/s, done.
Total 14 (delta 3), reused 0 (delta 0)
To git@github.com:schacon/simplegit.git
 * [new tag]         v1.5 -> v1.5
```



如果想要一次性推送很多标签，也可以使用带有 `--tags` 选项的 `git push` 命令。 这将会把所有不在远程仓库服务器上的标签全部传送到那里。

```
$ git push origin --tags
Counting objects: 1, done.
Writing objects: 100% (1/1), 160 bytes | 0 bytes/s, done.
Total 1 (delta 0), reused 0 (delta 0)
To git@github.com:schacon/simplegit.git
 * [new tag]         v1.4 -> v1.4
 * [new tag]         v1.4-lw -> v1.4-lw
```

*现在，当其他人从仓库中克隆或拉取，他们也能到你的那些标签。*

*使用 `git push <remote> --tags` 会推送两种标签，不会区分轻量标签和附注标签， 没有简单的选项能够让你只选择推送一种标签。*



#### 删除标签

`git tag -d <tagname>` 命令用于删除本地仓库上的标签，以下命令删除一个轻量标签：

```
$ git tag -d v1.4-lw
Deleted tag 'v1.4-lw' (was e7d5add)
```

***上述命令并不会从任何远程仓库中移除这个标签。***



使用 `git push <remote> :refs/tags/<tagname>` 命令更新远程仓库（删除标签信息）

```
$ git push origin :refs/tags/v1.4-lw
To /git@github.com:schacon/simplegit.git
 - [deleted]         v1.4-lw
```

*上面这种操作的含义是，将冒号前面的空值推送到远程标签名，从而高效地删除它。*



更直观的方式删除远程标签的命令：

```
$ git push origin --delete <tagname>
```



#### 检出标签

`git checkout` 命令检出到某个标签，用于查看某个标签所指向的文件版本。虽然这会使你的仓库处于“分离头指针（detached HEAD）”的状态，

```
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



如果你需要进行更改，比如你要修复旧版本中的错误，那么通常需要创建一个新分支：

```
$ git checkout -b version2 v2.0.0
Switched to a new branch 'version2'
```

如果在这之后又进行了一次提交，`version2` 分支就会因为这个改动向前移动， 此时它就会和 `v2.0.0` 标签稍微有些不同。



### 命令别名

`git config` 命令用于修改配置文件，可以用于为每一个命令设置一个别名。



一些好用的例子：

```
$ git config --global alias.co checkout
$ git config --global alias.br branch
$ git config --global alias.ci commit
$ git config --global alias.st status
```

*当要输入 `git commit` 时，只需要输入 `git ci`。*

*随着你继续不断地使用 Git，可能也会经常使用其他命令，所以创建别名时不要犹豫。*



在创建你认为应该存在的命令时这个技术会很有用。

例如，为了解决取消暂存文件的易用性问题，可以向 Git 中添加你自己的取消暂存别名：

```
$ git config --global alias.unstage 'reset HEAD --'
```

这会使下面的两个命令等价：

```
$ git unstage fileA
$ git reset HEAD -- fileA
```

这样看起来更清楚一些。



通常也会添加一个 `last` 命令，像这样：

```console
$ git config --global alias.last 'log -1 HEAD'
```

这样，可以轻松地看到最后一次提交：

```
$ git last
commit 66938dae3329c7aebe598c2246a8e6af90d04646
Author: Josh Goebel <dreamer3@example.com>
Date:   Tue Aug 26 19:48:51 2008 +0800

    test for current head

    Signed-off-by: Scott Chacon <schacon@example.com>
```



## 分支

### 分支的本质

**回顾 Git 保存文件的方式**

Git 保存的不是文件的变化或者差异，而是一系列不同时刻的**快照** 。虽然你可以使用 `git diff` 等命令来比较不同提交之间的变化，这其实是 Git 在后台为你计算出来的，它通过比对不同快照的内容来呈现差异。



在进行提交操作时，Git 会保存一个提交对象（commit object），该提交对象会包含一个指向<u>暂存内容快照的指针、作者的姓名和邮箱、提交时输入的信息、**指向它的父对象的指针**</u>。

根据提交类型，提交对象所包含的父对象指针数量也有所不同：

- **首次提交**：没有父对象。
- **普通提交**：有一个父对象。
- **合并提交**：有多个父对象。



为了更加形象地说明，我们假设现在有一个工作目录，里面包含了三个将要被暂存和提交的文件。

当你执行暂存操作时，Git 会为每一个文件计算校验和（SHA-1 哈希算法）然后会把当前版本的文件快照保存到 Git 仓库中 （Git 使用 *blob* 对象来保存它们），最终将校验和加入到暂存区域等待提交。



使用 `git commit` 命令将暂存区的文件提交。

```
$ git add README test.rb LICENSE
$ git commit -m 'The initial commit of my project'
```

当使用 `git commit` 进行提交操作时，Git 会先计算每一个子目录（本例中只有项目根目录）的校验和， 然后在 Git 仓库中这些校验和保存为树对象（tree object）。

随后，Git 便会创建一个提交对象， 它除了包含上面提到的那些信息外，还包含指向这个树对象（项目根目录）的指针。 如此一来，Git 就可以在需要的时候重现此次保存的快照。



现在，Git 仓库中有五个对象：三个 *blob* 对象（保存着文件快照）、一个 **树** 对象 （记录着目录结构和 blob 对象索引）以及一个 **提交** 对象（包含着指向前述树对象的指针和所有提交信息）。

![image-20250926105617653](./images/Git%20new.assets/image-20250926105617653.png)



做些修改后再次提交，那么这次产生的提交对象会包含一个指向上次提交对象（父对象）的指针。

![image-20250926110013925](./images/Git%20new.assets/image-20250926110013925-1758855614727-1-1758855617514-3.png)



Git 的分支本质上是一个**指向特定提交对象的可变指针**。虽然在查看某个分支时，你可以浏览其当前和历史提交，但分支本身并不包含任何提交历史信息，也不“拥有”任何提交。

分支的历史提交是通过 Git 工具，根据该分支当前指向的**提交对象（commit object）** 中的父提交指针，逐层追溯计算出来的。从技术角度看，一个分支只是一个简单的引用文件，内部存储着一个提交对象的**SHA-1 哈希值**。



Git 的默认分支名字是 `master`。 在多次提交操作之后，你其实已经有一个指向最后那个提交对象的 `master` 分支。 `master` 分支会在每次提交时自动向前移动。

![image-20250926110610179](./images/Git%20new.assets/image-20250926110610179.png)

*Git 的 `master` 分支并不是一个特殊分支。 它就跟其它分支完全没有区别。 之所以几乎每一个仓库都有 master 分支，是因为 `git init` 命令默认创建它，并且大多数人都懒得去改动它。*



### 基本操作

#### 分支创建

Git 工具创建分支，它只是为你创建了一个可以移动的新的指针。使用 `git branch` 命令实现：

```console
$ git branch testing
```

*这会在当前所在的提交对象上创建一个指针。*

![image-20250926110902036](./images/Git%20new.assets/image-20250926110902036-1758856143531-5.png)





Git 中存在一个名为 `HEAD` 的特殊指针，正常情况下 HEAD 会指向一个分支，即指向当前所在的本地分支（译注：将 `HEAD` 想象为当前分支的别名）。

如果使用 `checkout` 命令直接检出到一个特定的提交、一个标签（`tag`）或一个远程分支的提交时，`HEAD` 会**直接指向那个提交对象**（该对象的哈希值）。此时 HEAD 不位于任何一个分支上，HEAD 处于**分离头状态 (Detached HEAD)**。在这种状态下，如果你进行新的提交，这个提交将不会属于任何分支。

在本例中，你仍然在 `master` 分支上。 因为 `git branch` 命令仅仅**创建**一个新分支，并不会自动切换到新分支中去。

![image-20250926111031392](./images/Git%20new.assets/image-20250926111031392.png)



你可以简单地使用 `git log` 命令，并使用 `--decorate` 参数，查看**指向当前提交（也就是 `HEAD` 所指向的提交）的所有分支**。

```
$ git log --oneline --decorate
f30ab (HEAD -> master, testing) add feature #32 - ability to add new formats to the central interface
34ac2 Fixed bug #1328 - stack overflow under certain conditions
98ca9 The initial commit of my project
```

*当前 `master` 和 `testing` 分支均指向校验和以 `f30ab` 开头的提交对象。*



#### 分支切换

`git checkout` 命令用于切换到一个已存在的分支，现在切换到新创建的 `testing` 分支去：

```
$ git checkout testing
```

这样 `HEAD` 就指向 `testing` 分支了。

![image-20250926111749065](./images/Git%20new.assets/image-20250926111749065.png)

在切换分支时，一定要注意你工作目录里的文件会被改变。 如果是切换到一个较旧的分支，你的工作目录会恢复到该分支最后一次提交时的样子。 **如果 Git 不能干净利落地完成这个任务，它将禁止切换分支。**

**工作目录中存在已修改、但未暂存的文件**

假设你在 `master` 分支上修改了 `main.py` 文件，但未将其添加到暂存区（未执行 `git add`）。此时，如果你尝试切换到 `dev` 分支，且 `dev` 分支上的 `main.py` 文件与你本地未修改的版本（即 `master` 分支上最后一次提交的版本）存在差异，Git 将拒绝切换。这是为了防止 `dev` 分支的文件覆盖你未暂存的修改，导致数据丢失。Git 会报错并中止操作以保护你的工作成果。

**工作目录中已修改的文件全部添加到了暂存区**

当你执行 `git add` 后，这些修改的“快照”已被安全地记录在暂存区（Staging Area）中。Git 认为这些工作已妥善保存，即使它们尚未提交。因此，在这种情况下，切换分支不会导致已暂存的修改丢失。

你会成功切换到新分支。执行 `git status` 时，你会发现这些已暂存的文件在新分支上依然处于暂存状态，等待你的后续提交。



再提交一次，HEAD 分支（即 HEAD 指向的分支）会随着提交操作自动向前移动：

```
$ vim test.rb
$ git commit -a -m 'made a change'
```

虽然 `testing` 分支向前移动了，但是 `master` 分支却没有，它仍然指向原来的提交（`f30ab`）。

![image-20250926111936553](./images/Git%20new.assets/image-20250926111936553.png)

现在切换回 `master` 分支，一是使 HEAD 指回 `master` 分支，二是将工作目录恢复成 `master` 分支所指向的快照内容。

当你切换回 `master` 分支时，工作目录的内容会恢复到 `master` 指向的那个较旧的版本。这相当于暂时忽略了 `testing` 分支上的修改，让你能从 `master` 分支的当前状态出发，向一个全新的方向进行开发。

![image-20250926122409576](./images/Git%20new.assets/image-20250926122409576.png)



对项目中的文件内容进行修改并提交：

```
$ vim test.rb
$ git commit -a -m 'made other changes'
```

现在，这个项目的提交历史已经产生了分叉。因为刚才你创建了一个新分支，并切换过去进行了一些工作，随后又切换回 master 分支进行了另外一些工作。 上述两次改动针对的是不同分支：你可以在不同分支间不断地来回切换和工作，并在时机成熟时将它们合并起来。

![image-20250926122947162](./images/Git%20new.assets/image-20250926122947162.png)



你可以简单地使用 `git log` 命令查看分叉历史。 运行 `git log --oneline --decorate --graph --all` ，它会输出你的提交历史、各个分支的指向以及项目的分支分叉情况。

```
$ git log --oneline --decorate --graph --all
* c2b9e (HEAD, master) made other changes
| * 87ab2 (testing) made a change
|/
* f30ab add feature #32 - ability to add new formats to the
* 34ac2 fixed bug #1328 - stack overflow under certain conditions
* 98ca9 initial commit of my project
```



由于 Git 的分支实质上仅是包含所指对象校验和（长度为 40 的 SHA-1 值字符串）的文件，所以它的创建和销毁都异常高效。 创建一个新分支就相当于往一个文件中写入 41 个字节（40 个字符和 1 个换行符）。



#### 创建分支并切换

创建一个新分支后立即切换过去，可以使用 `git checkout -b <newbranchname>` 一条命令搞定。



### 分支的新建与合并

让我们来看一个简单的分支新建与分支合并的例子，实际工作中你可能会用到类似的工作流。 你将经历如下步骤：

1. 开发某个网站。
2. 为实现某个新的用户需求，创建一个分支。
3. 在这个分支上开展工作。

正在此时，你突然接到一个电话说有个很严重的问题需要紧急修补。 你将按照如下方式来处理：

1. 切换到你的线上分支（production branch）。
2. 为这个紧急任务新建一个分支，并在其中修复它。
3. 在测试通过之后，切换回线上分支，然后合并这个修补分支，最后将改动推送到线上分支。
4. 切换回你最初工作的分支上，继续工作。



#### 新建分支

首先，我们假设你正在你的项目上工作，并且在 `master` 分支上已经有了一些提交。

![image-20250926145058117](./images/Git%20new.assets/image-20250926145058117.png)



现在，你已经决定要解决你的公司使用的问题追踪系统中的 #53 问题。 想要新建一个分支并同时切换到那个分支上，你可以运行一个带有 `-b` 参数的 `git checkout` 命令：

```
$ git checkout -b iss53
Switched to a new branch "iss53"
```



它是下面两条命令的简写：

```
$ git branch iss53
$ git checkout iss53
```

![image-20250926145223593](./images/Git%20new.assets/image-20250926145223593.png)

你继续在 #53 问题上工作，并且做了一些提交。 在此过程中，`iss53` 分支在不断的向前推进，因为你已经检出到该分支 （也就是说，你的 `HEAD` 指针指向了 `iss53` 分支）

```console
$ vim index.html
$ git commit -a -m 'added a new footer [issue 53]'
```

![image-20250926145243328](./images/Git%20new.assets/image-20250926145243328.png)



现在你接到那个电话，有个紧急问题等待你来解决，要切换回 `master` 分支。

在你这么做之前，要留意你的工作目录和暂存区里那些还没有被提交的修改， 它可能会和你即将检出的分支产生冲突从而阻止 Git 切换到该分支。 最好的方法是，在你切换分支之前，保持好一个干净的状态。 有一些方法可以绕过这个问题（即，贮藏（stashing） 和 修补提交（commit amending））。

现在，我们假设你已经把你的修改全部提交了，这时你可以切换回 `master` 分支了：

```
$ git checkout master
Switched to branch 'master'
```



这个时候，你的工作目录和你在开始 #53 问题之前一模一样，现在你可以专心修复紧急问题了。

当你切换分支的时候，Git 会重置你的工作目录，使其看起来像回到了你在那个分支上最后一次提交的样子。 Git 会自动添加、删除、修改文件以确保此时你的工作目录和这个分支最后一次提交时的样子一模一样。

接下来，你要修复这个紧急问题。 我们来建立一个 `hotfix` 分支，在该分支上工作直到问题解决：

```
$ git checkout -b hotfix
Switched to a new branch 'hotfix'
$ vim index.html
$ git commit -a -m 'fixed the broken email address'
[hotfix 1fb7853] fixed the broken email address
 1 file changed, 2 insertions(+)
```

![image-20250926145445780](./images/Git%20new.assets/image-20250926145445780.png)



#### 快进合并

你可以运行你的测试，确保你的修改是正确的，然后将 `hotfix` 分支合并回你的 `master` 分支来部署到线上。 

你可以使用 `git merge` 命令来达到上述目的：

```
$ git checkout master
$ git merge hotfix
Updating f42c576..3a0874c
Fast-forward
 index.html | 2 ++
 1 file changed, 2 insertions(+)
```

在合并的时候，你应该注意到了“快进（fast-forward）”这个词。 由于你想要合并的分支 `hotfix` 所指向的提交 `C4` 是你所在的提交 `C2` 的直接后继， 因此 Git 会直接将指针向前移动。换句话说，当你试图合并两个分支时， 如果顺着一个分支走下去能够到达另一个分支，那么 Git 在合并两者的时候， 只会简单的将指针向前推进（指针右移），因为这种情况下的合并操作没有需要解决的分歧——这就叫做 “快进（fast-forward）”。



现在，最新的修改已经在 `master` 分支所指向的提交快照中，你可以着手发布该修复了。

![image-20250926145528230](./images/Git%20new.assets/image-20250926145528230.png)



#### 删除分支

关于这个紧急问题的解决方案发布之后，你准备回到被打断之前时的工作中。 然而，你应该先删除 `hotfix` 分支，因为你已经不再需要它了 —— `master` 分支已经指向了同一个位置。 

你可以使用带 `-d` 选项的 `git branch` 命令来删除分支：

```
$ git branch -d hotfix
Deleted branch hotfix (3a0874c).
```



现在你可以切换回你正在工作的分支继续你的工作，也就是针对 #53 问题的那个分支（iss53 分支）。

```
$ git checkout iss53
Switched to branch "iss53"
$ vim index.html
$ git commit -a -m 'finished the new footer [issue 53]'
[iss53 ad82d7a] finished the new footer [issue 53]
1 file changed, 1 insertion(+)
```

![image-20250926145608898](./images/Git%20new.assets/image-20250926145608898.png)

你在 `hotfix` 分支上所做的工作并没有包含到 `iss53` 分支中。 如果你需要拉取 `hotfix` 所做的修改，你可以使用 `git merge master` 命令将 `master` 分支合并入 `iss53` 分支，或者你也可以等到 `iss53` 分支完成其使命，再将其合并回 `master` 分支。



#### 分支的合并

假设你已经修正了 #53 问题，并且打算将你的工作合并入 `master` 分支。 为此，你需要合并 `iss53` 分支到 `master` 分支，这和之前你合并 `hotfix` 分支所做的工作差不多。 

你只需要检出到你想**合并入的分支**，然后运行 `git merge` 命令（**将 iss53 合并到 master 分支**）：

```
$ git checkout master
Switched to branch 'master'
$ git merge iss53
Merge made by the 'recursive' strategy.
index.html |    1 +
1 file changed, 1 insertion(+)
```

将一个分支（如 `iss53`）合并到当前分支（如 `master`）与反向操作是完全不同的，因为合并操作只更新当前所在的分支。当您在 `master` 分支上合并 `iss53` 时，Git 会创建一个拥有两个父节点的新“合并提交”。随后，只有 `master` 分支的指针会移动到这个新的提交上，而 `iss53` 分支的指针则保持原位不变。



这和你之前合并 `hotfix` 分支的时候看起来有一点不一样。 在这种情况下，你的开发历史从一个更早的地方开始分叉开来（diverged）。 因为，`master` 分支所在提交并不是 `iss53` 分支所在提交的直接祖先，Git 不得不做一些额外的工作。 出现这种情况的时候，Git 会使用两个分支的末端所指的快照（`C4` 和 `C5`）以及这两个分支的公共祖先（`C2`），做一个简单的三方合并。

![image-20250926150938536](./images/Git%20new.assets/image-20250926150938536.png)

和之前将分支指针向前推进所不同的是，Git 将此次三方合并的结果做了一个新的快照并且自动创建一个新的提交指向它。 这个被称作一次合并提交，它的特别之处在于他有不止一个父提交。

![image-20250926151018461](./images/Git%20new.assets/image-20250926151018461.png)

既然你的修改已经合并进来了，就不再需要 `iss53` 分支了。 现在你可以在任务追踪系统中关闭此项任务，并删除这个分支。

```
$ git branch -d iss53
```



#### 三方合并机制

Git 的三方合并（Three-Way Merge）机制。这是一种在合并分支时用来整合不同变更的默认策略。

三方合并的核心思想是通过寻找一个**共同的祖先**（Common Ancestor）作为基准，来比较两个分支各自的变更，然后将这些变更整合在一起。



它被称为“三方”合并，是因为该算法会分析三个关键的提交（commit）：

1. **共同祖先 (The Base)**：两个待合并分支分叉前的最后一个共同提交。
2. **分支一的顶端 (HEAD)**：当前分支的最新提交。
3. **分支二的顶端 (The Other Branch)**：你想要合并进来的分支的最新提交。



**识别共同祖先**

Git 首先会遍历两个分支的历史，找到它们最近的共同祖先提交。



**计算差异（Diff）**

计算出从**共同祖先**到**分支一顶端**的变更内容（一个补丁）。

计算出从**共同祖先**到**分支二顶端**的变更内容（另一个补丁）。



**应用变更**

Git 将上述两个补丁同时应用到**共同祖先**的代码快照上。

**无冲突**，如果两个分支的变更发生在文件的不同区域，Git 会顺利地将两边的修改整合起来，并自动创建一个新的**合并提交 (Merge Commit)**。这个新的提交会有两个父提交，分别指向原来的两个分支顶端。

**冲突**，如果两个分支修改了同一个文件的同一行或相近区域，Git 无法自动决定采用哪个版本。此时，合并过程会暂停，Git 会在冲突文件中标记出冲突区域，等待用户手动解决。





#### 合并时不自动提交

当 Git 执行`git merge` 命令并触发**三方合并（three-way merge）**时，需要合并两个分支。在这种情况下，Git 会尝试自动将两个分支的更改集成在一起。如果合并过程中没有冲突，Git会**自动创建一个新的提交（commit）**来记录这次合并。因此，你不需要手动执行`git commit`命令。

在Git中，如果你不希望 `git merge` 在成功合并后**自动创建一个新的提交**，而是想要手动控制提交过程，可以使用 `--no-commit` 参数。使用该参数后，Git会将合并的结果放入你的工作区和暂存区，但不会自动提交，你可以自行检查和提交。



将 new33 分支合并到 master 分支：

```
$ git checkout master
$ git merge --no-commit new33
Automatic merge went well; stopped before committing as requested
```

*翻译：自动合并进展顺利；按要求提交之前停止*



查看状态：

```
$ git status
On branch master
All conflicts fixed but you are still merging.
  (use "git commit" to conclude merge)

Changes to be committed:
        new file:   111


$ git diff --cached
diff --git a/111 b/111
new file mode 100644
index 0000000..e909a5a
--- /dev/null
+++ b/111
@@ -0,0 +1 @@
+111
```



执行 `git commit` 命令手动触发提交：

```
$ git commit -m "add 111 file"
[master 12c2f5d] add 111 file
```



#### 遇到冲突时的分支合并

如果你在两个不同的分支中，对同一个文件的同一个部分进行了不同的修改，Git 就没法干净的合并它们。

 如果你对 #53 问题的修改和有关 `hotfix` 分支的修改都涉及到同一个文件的同一处，在合并它们的时候就会产生合并冲突：

```console
$ git merge iss53
Auto-merging index.html
CONFLICT (content): Merge conflict in index.html
Automatic merge failed; fix conflicts and then commit the result.
```



此时 Git 做了合并，但是没有自动地创建一个新的合并提交。 Git 会暂停下来，等待你去解决合并产生的冲突。

你可以在合并冲突后的任意时刻使用 `git status` 命令来查看那些因包含合并冲突而处于未合并（unmerged）状态的文件：

```console
$ git status
On branch master
You have unmerged paths.
  (fix conflicts and run "git commit")

Unmerged paths:
  (use "git add <file>..." to mark resolution)

    both modified:      index.html

no changes added to commit (use "git add" and/or "git commit -a")
```



任何因包含合并冲突而有待解决的文件，都会以未合并状态标识出来。 Git 会在有冲突的文件中加入标准的冲突解决标记，这样你可以打开这些包含冲突的文件然后手动解决冲突。 

出现冲突的文件会包含一些特殊区段，看起来像下面这个样子：

```
<<<<<<< HEAD:index.html
<div id="footer">contact : email.support@github.com</div>
=======
<div id="footer">
 please contact us at support@github.com
</div>
>>>>>>> iss53:index.html
```



这表示 `HEAD` 所指示的版本（也就是你的 `master` 分支所在的位置，因为你在运行 merge 命令的时候已经检出到了这个分支）在这个区段的上半部分（`=======` 的上半部分），而 `iss53` 分支所指示的版本在 `=======` 的下半部分。

为了解决冲突，你必须选择使用由 `=======` 分割的两部分中的一个，或者你也可以自行合并这些内容。

例如，你可以通过把这段内容换成下面的样子来解决冲突：

```
<div id="footer">
please contact us at email.support@github.com
</div>
```

上述的冲突解决方案仅保留了其中一个分支的修改，并且 `<<<<<<<` , `=======` , 和 `>>>>>>>` 这些行被完全删除了。



在你解决了所有文件里的冲突之后，对每个文件使用 `git add` 命令来将其标记为冲突已解决。 一旦暂存这些原本有冲突的文件，Git 就会将它们标记为冲突已解决。

你可以再次运行 `git status` 来确认所有的合并冲突都已被解决：

```
$ git status
On branch master
All conflicts fixed but you are still merging.
  (use "git commit" to conclude merge)

Changes to be committed:

    modified:   index.html
```



如果你对结果感到满意，并且确定之前有冲突的文件都已经暂存了，这时你可以输入 `git commit` 来完成合并提交。 

```
git commit
```



默认情况下提交信息看起来像下面这个样子：

```
Merge branch 'iss53'

Conflicts:
    index.html
#
# It looks like you may be committing a merge.
# If this is not correct, please remove the file
#	.git/MERGE_HEAD
# and try again.


# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
# On branch master
# All conflicts fixed but you are still merging.
#
# Changes to be committed:
#	modified:   index.html
#
```

如果你觉得上述的信息不够充分，不能完全体现分支合并的过程，你可以修改上述信息， 添加一些细节给未来检视这个合并的读者一些帮助，告诉他们你是如何解决合并冲突的，以及理由是什么。



### 分支管理

现在已经创建、合并、删除了一些分支，让我们看看一些常用的分支管理工具。



#### 查看分支列表

`git branch` 命令不只是可以创建与删除分支。 如果不加任何参数运行它，会得到当前所有分支的一个列表：

```
$ git branch
  iss53
* master
  testing
```

注意 `master` 分支前的 `*` 字符：它代表现在检出的那一个分支（也就是说，当前 `HEAD` 指针所指向的分支）。

这意味着如果在这时候提交，`master` 分支将会随着新的工作向前移动。 



#### 查看分支的最后提交

如果需要查看每一个分支的最后一次提交，可以运行 `git branch -v` 命令：

```
$ git branch -v
  iss53   93b412c fix javascript issue
* master  7a98805 Merge branch 'iss53'
  testing 782fd34 add scott to the author list in the readmes
```



#### 已经合并的分支

`--merged` 与 `--no-merged` 这两个有用的选项可以过滤这个列表中已经合并或尚未合并到当前分支的分支。 

如果要查看哪些分支已经合并到当前分支，可以运行 `git branch --merged`：

```
$ git branch --merged
  iss53
* master
```

因为之前已经合并了 `iss53` 分支，所以现在看到它在列表中。

在这个列表中分支名字前没有 `*` 号的分支通常可以使用 `git branch -d` 删除掉；你已经将它们的工作整合到了另一个分支，所以并不会失去任何东西。



#### 未合并的分支

查看所有包含未合并工作的分支，可以运行 `git branch --no-merged`：

```
$ git branch --no-merged
  testing
```



这里显示了其他分支。 因为它包含了还未合并的工作，尝试使用 `git branch -d` 命令删除它时会失败：

```console
$ git branch -d testing
error: The branch 'testing' is not fully merged.
If you are sure you want to delete it, run 'git branch -D testing'.
```

如果真的想要删除分支并丢掉那些工作，如同帮助信息里所指出的，可以使用 `-D` 选项强制删除它。



上面描述的选项 `--merged` 和 `--no-merged` 会在没有给定提交或分支名作为参数时， 分别列出已合并或未合并到**当前**分支的分支。

你总是可以提供一个附加的参数来查看其它分支的合并状态而不必检出它们。 例如，查看尚未合并到 `master` 分支：

```
$ git checkout testing
$ git branch --no-merged master
  topicA
  featureB
```



### 分支开发工作流

#### 长期分支

因为 Git 使用简单的三方合并，所以就算在一段较长的时间内，反复把一个分支合并入另一个分支，也不是什么难事。 也就是说，在整个项目开发周期的不同阶段，你可以同时拥有多个开放的分支；你可以定期地把某些主题分支合并入其他分支中。

许多使用 Git 的开发者都喜欢使用这种方式来工作，比如只在 `master` 分支上保留完全稳定的代码——有可能仅仅是已经发布或即将发布的代码。

他们还有一些名为 `develop` 或者 `next` 的平行分支，被用来做后续开发或者测试稳定性——这些分支不必保持绝对稳定，但是一旦达到稳定状态，它们就可以被合并入 `master` 分支了。

这样，在确保这些已完成的主题分支（短期分支，比如之前的 `iss53` 分支）能够通过所有测试，并且不会引入更多 bug 之后，就可以合并入主干分支中，等待下一次的发布。



事实上我们刚才讨论的，是随着你的提交而不断右移的指针。 稳定分支的指针总是在提交历史中落后一大截，而前沿分支的指针往往比较靠前。

![image-20250926163802820](./images/Git%20new.assets/image-20250926163802820.png)



通常把他们想象成流水线（work silos）可能更好理解一点，那些经过测试考验的提交会被遴选到更加稳定的流水线上去。

![image-20250926163821806](./images/Git%20new.assets/image-20250926163821806.png)





你可以用这种方法维护不同层次的稳定性。 一些大型项目还有一个 `proposed`（建议） 或 `pu: proposed updates`（建议更新）分支，它可能因包含一些不成熟的内容而不能进入 `next` 或者 `master` 分支。 

这么做的目的是使你的分支具有不同级别的稳定性；当它们具有一定程度的稳定性后，再把它们合并入具有更高级别稳定性的分支中。 

再次强调一下，使用多个长期分支的方法并非必要，但是这么做通常很有帮助，尤其是当你在一个非常庞大或者复杂的项目中工作时。



#### 主题分支

主题分支对任何规模的项目都适用。 主题分支是一种短期分支，它被用来实现单一特性或其相关工作。在 Git 中一天之内多次创建、使用、合并、删除分支都很常见。

在上面的示例中创建的 `iss53` 和 `hotfix` 主题分支中看到过这种用法。上面示例用到的主题分支（`iss53` 和 `hotfix` 分支）中提交了一些更新，并且在它们合并入主干分支之后，你又删除了它们。

这项技术能使你快速并且完整地进行上下文切换（context-switch）——因为你的工作被分散到不同的流水线中，在不同的流水线中每个分支都仅与其目标特性相关，因此，在做代码审查之类的工作的时候就能更加容易地看出你做了哪些改动。 你可以把做出的改动在主题分支中保留几分钟、几天甚至几个月，等它们成熟之后再合并，而不用在乎它们建立的顺序或工作进度。



考虑这样一个例子，你在 `master` 分支上工作到 `C1`，这时为了解决一个问题而新建 `iss91` 分支，在 `iss91` 分支上工作到 `C4`，然而对于那个问题你又有了新的想法，于是你再新建一个 `iss91v2` 分支试图用另一种方法解决那个问题，接着你回到 `master` 分支工作了一会儿，你又冒出了一个不太确定的想法，你便在 `C10` 的时候新建一个 `dumbidea` 分支，并在上面做些实验。 你的提交历史看起来像下面这个样子：

![image-20250926164057872](./images/Git%20new.assets/image-20250926164057872.png)



现在，我们假设两件事情：你决定使用第二个方案来解决那个问题，即使用在 `iss91v2` 分支中方案。 另外，你将 `dumbidea` 分支拿给你的同事看过之后，结果发现这是个惊人之举。 这时你可以抛弃 `iss91` 分支（即丢弃 `C5` 和 `C6` 提交），然后把另外两个分支合并入主干分支。 最终你的提交历史看起来像下面这个样子：

![image-20250926164108245](./images/Git%20new.assets/image-20250926164108245.png)

### 远程分支

#### 概念

远程以 `<remote>/<branch>` 的形式命名。 例如，如果你想要看你最后一次与远程仓库 `origin` 通信时 `master` 分支的状态，你可以查看 `origin/master` 分支。

远程仓库名字 “origin” 与分支名字 “master” 一样，在 Git 中并没有任何特别的含义一样。 同时 “master” 是当你运行 `git init` 时默认的起始分支名字，原因仅仅是它的广泛使用， “origin” 是当你运行 `git clone` 时默认的远程仓库名字。 如果你运行 `git clone -o booyah`，那么你默认的远程分支名字将会是 `booyah/master`。

你与同事合作解决一个问题并且他们推送了一个 `iss53` 分支，你可能有自己的本地 `iss53` 分支， 然而在服务器上的分支会以 `origin/iss53` 来表示。



假设你的网络里有一个在 `git.ourcompany.com` 的 Git 服务器。 如果你从这里克隆，Git 的 `clone` 命令会为你自动将其命名为 `origin`，拉取它的所有数据， 创建一个指向它的 `master` 分支的指针，并且在本地将其命名为 `origin/master`。

Git 也会给你一个与 origin 的 `master` 分支在指向同一个地方的本地 `master` 分支，这样你就有工作的基础。

![image-20250926184935190](./images/Git%20new.assets/image-20250926184935190.png)



如果你在本地的 `master` 分支做了一些工作，在同一段时间内有其他人推送提交到 `git.ourcompany.com` 并且更新了它的 `master` 分支，这就是说你们的提交历史已走向不同的方向。 

即便这样，只要你保持不与 `origin` 服务器连接（并拉取数据），你的 `origin/master` 指针就不会移动。

![image-20250926185033481](./images/Git%20new.assets/image-20250926185033481.png)



现在，可以运行 `git fetch teamone` 来抓取远程仓库 `teamone` 有而本地没有的数据。 因为那台服务器上现有的数据是 `origin` 服务器上的一个子集， 所以 Git 并不会抓取数据而是会设置远程跟踪分支 `teamone/master` 指向 `teamone` 的 `master` 分支。

![image-20250926185101041](./images/Git%20new.assets/image-20250926185101041.png)



#### 推送

当你想要公开分享一个分支时，需要将其推送到有写入权限的远程仓库上。 本地的分支并不会自动与远程仓库同步——你必须显式地推送想要分享的分支。 这样，你就可以把不愿意分享的内容放到私人分支上，而将需要和别人协作的内容推送到公开分支。



如果希望和别人一起在名为 `serverfix` 的分支上工作，你可以像推送第一个分支那样推送它。 运行 `git push <remote> <branch>`:

```
$ git push origin serverfix
Counting objects: 24, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (15/15), done.
Writing objects: 100% (24/24), 1.91 KiB | 0 bytes/s, done.
Total 24 (delta 2), reused 0 (delta 0)
To https://github.com/schacon/simplegit
 * [new branch]      serverfix -> serverfix
```

你也可以运行 `git push origin serverfix:serverfix`， 它会做同样的事——也就是说“推送本地的 `serverfix` 分支，将其作为远程仓库的 `serverfix` 分支” 可以通过这种格式来推送本地分支到一个命名不相同的远程分支。

如果并不想让远程仓库上的分支叫做 `serverfix`，可以运行 `git push origin serverfix:awesomebranch` 来将本地的 `serverfix` 分支推送到远程仓库上的 `awesomebranch` 分支。



下一次其他协作者从服务器上抓取数据时，他们会在本地生成一个远程分支 `origin/serverfix`，指向服务器的 `serverfix` 分支的引用：

```
$ git fetch origin
remote: Counting objects: 7, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 3 (delta 0)
Unpacking objects: 100% (3/3), done.
From https://github.com/schacon/simplegit
 * [new branch]      serverfix    -> origin/serverfix
```

要特别注意的一点是当抓取到新的远程跟踪分支时，本地不会自动生成一个新的 `serverfix` 分支，只有一个不可以修改的 `origin/serverfix` 指针。



可以运行 `git merge origin/serverfix` 将这些工作合并到当前所在的分支。 如果想要在自己的 `serverfix` 分支上工作，可以将其建立在远程跟踪分支之上：

```
$ git checkout -b serverfix origin/serverfix
Branch serverfix set up to track remote branch serverfix from origin.
Switched to a new branch 'serverfix'
```

这会给你一个用于工作的本地分支，并且起点位于 `origin/serverfix`。



#### 跟踪分支

从一个远程跟踪分支检出一个本地分支会自动创建所谓的“跟踪分支”（它跟踪的分支叫做“上游分支”）。 跟踪分支是与远程分支有直接关系的本地分支。 如果在一个跟踪分支上输入 `git pull`，Git 能自动地识别去哪个服务器上抓取、合并到哪个分支。

当克隆一个仓库时，它通常会自动地创建一个跟踪 `origin/master` 的 `master` 分支

最简单的实例就是像之前看到的那样，运行 `git checkout -b <branch> <remote>/<branch>`。这样会创建一个 `<branch>` 分支并且跟踪远程分支 `<remote>/<branch>` 。



Git 提供了 `--track` 快捷方式：

```
$ git checkout --track origin/serverfix
Branch serverfix set up to track remote branch serverfix from origin.
Switched to a new branch 'serverfix'
```



如果你尝试检出的分支 (a) 不存在且 (b) 刚好只有一个名字与之匹配的远程分支，那么 Git 就会为你创建一个跟踪分支：

```
$ git checkout serverfix
Branch serverfix set up to track remote branch serverfix from origin.
Switched to a new branch 'serverfix'
```



如果想要将本地分支与远程分支设置为不同的名字，你可以轻松地使用上一个命令增加一个不同名字的本地分支：

```
$ git checkout -b sf origin/serverfix
Branch sf set up to track remote branch serverfix from origin.
Switched to a new branch 'sf'
```

现在，本地分支 `sf` 会自动从 `origin/serverfix` 拉取。



设置已有的本地分支跟踪一个刚刚拉取下来的远程分支，或者想要修改正在跟踪的上游分支， 你可以在任意时间使用 `-u` 或 `--set-upstream-to` 选项运行 `git branch` 来显式地设置。

```
$ git branch -u origin/serverfix
Branch serverfix set up to track remote branch serverfix from origin.
```



当设置好跟踪分支后，可以通过简写 `@{upstream}` 或 `@{u}` 来引用它的上游分支。 所以在 `master` 分支时并且它正在跟踪 `origin/master` 时，如果愿意的话可以使用 `git merge @{u}` 来取代 `git merge origin/master`。



如果想要查看设置的所有跟踪分支，可以使用 `git branch` 的 `-vv` 选项。 这会将所有的本地分支列出来并且包含更多的信息，如每一个分支正在跟踪哪个远程分支与本地分支是否是领先、落后或是都有。

```
$ git branch -vv
  iss53     7e424c3 [origin/iss53: ahead 2] forgot the brackets
  master    1ae2a45 [origin/master] deploying index fix
* serverfix f8674d9 [teamone/server-fix-good: ahead 3, behind 1] this should do it
  testing   5ea463a trying something new
```

这里可以看到 `iss53` 分支正在跟踪 `origin/iss53` 并且 “ahead” 是 2，意味着本地有两个提交还没有推送到服务器上。 也能看到 `master` 分支正在跟踪 `origin/master` 分支并且是最新的。

接下来可以看到 `serverfix` 分支正在跟踪 `teamone` 服务器上的 `server-fix-good` 分支并且领先 3 落后 1， 意味着服务器上有一次提交还没有合并入同时本地有三次提交还没有推送。 最后看到 `testing` 分支并没有跟踪任何远程分支。



需要重点注意的一点是这些数字的值来自于你从每个服务器上最后一次抓取的数据。 这个命令并没有连接服务器，它只会告诉你关于本地缓存的服务器数据。 如果想要统计最新的领先与落后数字，需要在运行此命令前抓取所有的远程仓库。 可以像这样做：

```
$ git fetch --all; git branch -vv
```



#### 拉取

当 `git fetch` 命令从服务器上抓取本地没有的数据时，它并不会修改工作目录中的内容。 它只会获取数据然后让你自己合并。然而，有一个命令叫作 `git pull` 在大多数情况下它的含义是一个 `git fetch` 紧接着一个 `git merge` 命令。 

如果有一个跟踪分支，不管它是显式地设置还是通过 `clone` 或 `checkout` 命令为你创建的，`git pull` 都会查找当前分支所跟踪的服务器与分支， 从服务器上抓取数据然后尝试合并入那个远程分支。

由于 `git pull` 的魔法经常令人困惑所以通常单独显式地使用 `fetch` 与 `merge` 命令会更好一些。



#### 删除远程分支

假设你已经通过远程分支做完所有的工作了——也就是说你和你的协作者已经完成了一个特性， 并且将其合并到了远程仓库的 `master` 分支（或任何其他稳定代码分支）。 可以运行带有 `--delete` 选项的 `git push` 命令来删除一个远程分支。

如果想要从服务器上删除 `serverfix` 分支，运行下面的命令：

```
$ git push origin --delete serverfix
To https://github.com/schacon/simplegit
 - [deleted]         serverfix
```

基本上这个命令做的只是从服务器上移除这个指针。 Git 服务器通常会保留数据一段时间直到垃圾回收运行，所以如果不小心删除掉了，通常是很容易恢复的。



### 变基

在 Git 中整合来自不同分支的修改主要有两种方法：`merge` 以及 `rebase`。

在开始使用变基之前回顾**分支合并**的基本例子，你会看到开发任务分叉到两个不同分支，又各自提交了更新。

![image-20250927103122809](./images/Git%20new.assets/image-20250927103122809.png)

整合分支最容易的方法是 `merge` 命令。 它会把两个分支的最新快照（`C3` 和 `C4`）以及二者最近的共同祖先（`C2`）进行三方合并，合并的结果是生成一个新的快照（并提交）。

![image-20250927103133617](./images/Git%20new.assets/image-20250927103133617.png)



#### 变基的基本操作

在 Git 中，**变基（rebase）**操作是通过使用 `rebase` 命令**将提交到某一分支上的所有修改都移至另一分支上**。

在这个例子中，你可以检出 `experiment` 分支，然后将它变基到 `master` 分支上：

```
$ git checkout experiment
$ git rebase master
First, rewinding head to replay your work on top of it...
Applying: added staged command
```



它的原理是首先找到这两个分支（即当前分支 `experiment`、变基操作的目标基底分支 `master`） 的最近共同祖先 `C2`，然后对比当前分支相对于该祖先的历次提交，提取相应的修改并存为临时文件， 然后将当前分支指向目标基底 `C3`，最后以此将之前另存为临时文件的修改依序应用。

![image-20250927103326096](./images/Git%20new.assets/image-20250927103326096.png)



现在回到 `master` 分支，进行一次快进合并。

```
$ git checkout master
$ git merge experiment
```



此时，`C4'` 指向的快照就和**分支合并产生的`C5`** 指向的快照一模一样了。 这两种整合方法的最终结果没有任何区别，但是变基使得提交历史更加整洁。 你在查看一个经过变基的分支的历史记录时会发现，尽管实际的开发工作是并行的， 但它们看上去就像是串行的一样，提交历史是一条直线没有分叉。

一般我们这样做的目的是为了确保在向远程分支推送时能保持提交历史的整洁——例如向某个其他人维护的项目贡献代码时。 在这种情况下，你首先在自己的分支里进行开发，当开发完成时你需要先将你的代码变基到 `origin/master` 上，然后再向主项目提交修改。 这样的话，该项目的维护者就不再需要进行整合工作，只需要快进合并便可。

请注意，无论是通过变基，还是通过三方合并，整合的最终结果所指向的快照始终是一样的，只不过提交历史不同罢了。 变基是将一系列提交按照原有次序依次应用到另一分支上，而合并是把最终结果合在一起。



#### 变基的原理

变基的本质是重写提交历史（Rewriting History），**将一个分支上的提交历史“移植”到另一个分支的最新位置上，从而创造出一个更整洁、线性的提交历史。**它通过创建一个新的、更线性的提交历史来整合变更。

**Git 保存的是快照（Snapshot），而不是差异（Diff）**。每个提交都是项目在那个时间点的完整快-照。但为了高效地完成变基，Git 在底层会巧妙地运用差异计算。



我们通过一个例子来理解这个过程：

假设你的仓库历史如下，`master` 和 `feature` 分支从提交 `E` 开始分叉：

```
      A---B---C   <-- feature (你在这里工作)
     /
D---E---F---G       <-- master (团队其他人更新了)
```



现在将 **feature** 分支变基到 **master** 分支。

```
$ git checkout feature
$ git rebase master
```



**Git 内部实现变基的完整步骤**

**确定共同祖先与待重放的提交序列**

Git 首先通过遍历 `feature` 分支与 `master` 分支的提交历史，找到它们最近的**共同祖先（在此示例中为提交 `E`）**。

一旦确定了共同祖先，Git 会收集当前 `feature` 分支上自该**共同祖先之后的所有提交（即 `A`, `B`, `C`）**，并将这个提交序列识别为后续需要**重放 (replay)** 的对象。



**重置分支基底并提取变更集**

Git 会将 `feature` 分支独有的**提交（`A`, `B`, `C`）所引入的变更内容逐个提取出来**，并以**补丁 (patch)** 的形式暂存在 `.git` 目录下的一个临时区域。

一个提交（Commit）所引入的变更，指的是该**提交指向的内容快照（Snapshot）与其父提交（Parent Commit）指向的内容快照**之间的**差异（Diff）**。这个差异的最终表现形式就是一个**补丁（Patch）**。

完成提取后，Git 会将 `feature` 分支的**指针 (HEAD)** 重置，使其直接指向 `master` 分支的最新提交 `G`，从而完成**基底 (base)** 的切换，为后续应用补丁做好准备。



**迭代式提交重放 (Iterative Commit Replay)**

这是变基操作的核心执行阶段。Git 会进入一个迭代循环，按原始顺序处理之前暂存的补丁序列（即从提交 A, B, C 中提取的变更）。

对于每一个补丁，Git 都会尝试将其应用到当前分支的 HEAD 指针所指向的提交之上。

这个 HEAD 最初指向新的基底（提交 G）。每一次成功的补丁应用都会生成一个全新的、拥有不同 SHA-1 值的**提交对象 (Commit Object)**。



**重放首次变更：生成提交 A'**

操作始于序列中的第一个补丁，即源自提交 `A` 的变更。Git 首先通过比较 `A` 和其原始父提交 `E` 的**树对象 (Tree Object)** 来获取该补丁。

Git 尝试将此补丁应用到当前 HEAD 指向的 `G` 的代码快照上。若应用成功且无冲突，Git 会创建一个新的提交 `A'`。这个新提交会沿用 `A` 的作者、提交信息等元数据，但其**父提交指针 (Parent Pointer)** 将指向 `G`，从而在提交历史上建立新的链接。

最后，当前分支的 HEAD 会从 `G` 移动到 `A'`。



**重放后续变更：生成提交 B'**

完成 `A'` 的创建后，Git 继续处理序列中的下一个补丁，即源自提交 `B` 的变更（通过比较 `B` 和其原始父提交 `A` 生成）。

Git 将此补丁应用到当前 HEAD（现为 `A'`）的代码快照上。应用成功后，会以相同的方式创建新的提交 `B'`。

`B'` 的父提交将是 `A'`，`B'` 包含了 `A'` 的所有内容以及 `B` 所引入的变更。随后，分支的 HEAD 从 `A'` 移动到 `B'`。



**完成重放与更新分支引用：生成 C'**

Git 会应用源自提交 `C` 的补丁（通过比较 `C` 和其原始父提交 `B` 生成）到 `B'` 的代码快照上，创建最终的新提交 `C'`，其父提交为 `B'`。在 `C'` 创建成功后，整个补丁序列处理完毕。



**更新 feature 指针**

所有提交都应用完毕后，Git 会将 `feature` 分支的指针移动到最后一个新生成的提交 `C'` 上。

`master` 分支的指针在整个过程中保持不变，始终指向 `G`。



**变基后的最终状态**

`master` 分支保持不变，`feature` 分支的历史被改写，形成了一条干净的线性历史。

```
               A'--B'--C'  <-- feature
             /
D---E---F---G              <-- master
```



#### 复杂变基

在对两个分支进行变基时，所生成的“重放”并不一定要在目标分支上应用，你也可以指定另外的一个分支进行应用。

你创建了一个主题分支 `server`，为服务端添加了一些功能，提交了 `C3` 和 `C4`。 然后从 `C3` 上创建了主题分支 `client`，为客户端添加了一些功能，提交了 `C8` 和 `C9`。 最后，你回到 `server` 分支，又提交了 `C10`。

![image-20250927112258431](./images/Git%20new.assets/image-20250927112258431.png)



假设你希望将 `client` 中的修改合并到主分支并发布，但暂时并不想合并 `server` 中的修改， 因为它们还需要经过更全面的测试。

这时，你就可以使用 `git rebase` 命令的 `--onto` 选项， 选中在 `client` 分支里但不在 `server` 分支里的修改（即 `C8` 和 `C9`），将它们在 `master` 分支上重放：

```console
$ git rebase --onto master server client
```

以上命令的意思是：“取出 `client` 分支，找出它从 `server` 分支分歧之后的补丁， 然后把这些补丁在 `master` 分支上重放一遍，让 `client` 看起来像直接基于 `master` 修改一样”。

![image-20250927112338346](./images/Git%20new.assets/image-20250927112338346.png)

现在可以快进合并 `master` 分支了。

```
$ git checkout master
$ git merge client
```

![image-20250927112400570](./images/Git%20new.assets/image-20250927112400570.png)



接下来你决定将 `server` 分支中的修改也整合进来。 使用 `git rebase <basebranch> <topicbranch>` 命令可以直接将主题分支 （即本例中的 `server`）变基到目标分支（即 `master`）上。 这样做能省去你先切换到 `server` 分支，再对其执行变基命令的多个步骤。

```
$ git rebase master server
```



server 中的代码被“续”到了 master 后面。

![image-20250927112445434](./images/Git%20new.assets/image-20250927112445434.png)



然后就可以快进合并主分支 `master` 了：

```
$ git checkout master
$ git merge server
```



至此，`client` 和 `server` 分支中的修改都已经整合到主分支里了， 你可以删除这两个分支，最终提交历史会变成图中的样子：

```
$ git branch -d client
$ git branch -d server
```

![image-20250927112525916](./images/Git%20new.assets/image-20250927112525916.png)



#### 变基的风险

变基操作的实质是**重写提交历史**，丢弃一些现有的提交，然后相应地新建一些内容一样但实际上不同的提交。

如果你已经将提交推送至某个仓库，而其他人也已经从该仓库拉取提交并进行了后续工作，此时，如果你用 `git rebase` 命令重新整理了提交并再次推送，事情就会变得一团糟。



让我们来看一个在公开的仓库上执行变基操作所带来的问题。

假设你从一个中央服务器克隆然后在它的基础上进行了一些开发。 你的提交历史如图所示：

![image-20250927142843071](./images/Git%20new.assets/image-20250927142843071.png)



然后，某人又向中央服务器提交了一些修改，其中还包括一次合并。 你抓取了这些在远程分支上的修改，并将其合并到你本地的开发分支，然后你的提交历史就会变成这样：

![image-20250927142857053](./images/Git%20new.assets/image-20250927142857053.png)



接下来，这个人又决定把合并操作回滚，改用变基；继而又用 `git push --force` 命令覆盖了服务器上的提交历史。 之后你从服务器抓取更新，会发现多出来一些新的提交。

![image-20250927142913725](./images/Git%20new.assets/image-20250927142913725.png)



结果就是你们两人的处境都十分尴尬。 如果你执行 `git pull` 命令，你将合并来自两条提交历史的内容，生成一个新的合并提交，最终仓库会如图所示：

![image-20250927142925706](./images/Git%20new.assets/image-20250927142925706.png)

此时如果你执行 `git log` 命令，你会发现有两个提交的作者、日期、日志居然是一样的，这会令人感到混乱。

此外，如果你将这一堆又推送到服务器上，你实际上是将那些已经被变基抛弃的提交又找了回来，这会令人感到更加混乱。 

很明显对方并不想在提交历史中看到 `C4` 和 `C6`，因为之前就是他把这两个提交通过变基丢弃的。



#### 用变基解决变基

如果你**真的**遭遇了类似的处境，Git 还有一些高级魔法可以帮到你。 如果团队中的某人强制推送并覆盖了一些你所基于的提交，你需要做的就是检查你做了哪些修改，以及他们覆盖了哪些修改。

实际上，Git 除了对整个提交计算 SHA-1 校验和以外，也对本次提交所引入的修改计算了校验和——即 “patch-id”。

如果你拉取被覆盖过的更新并将你手头的工作基于此进行变基的话，一般情况下 Git 都能成功分辨出哪些是你的修改，并把它们应用到新分支上。



举个例子，如果遇到前面提到的**有人推送了经过变基的提交，并丢弃了你的本地开发所基于的一些提交**那种情境，如果我们不是执行合并，而是执行 `git rebase teamone/master,` Git 将会：

- 检查哪些提交是我们的分支上独有的（C2，C3，C4，C6，C7）
- 检查其中哪些提交不是合并操作的结果（C2，C3，C4）
- 检查哪些提交在对方覆盖更新时并没有被纳入目标分支（只有 C2 和 C3，因为 C4 其实就是 C4'）
- 把查到的这些提交应用在 `teamone/master` 上面



“哪些提交在对方覆盖更新时并没有被纳入目标分支”，其核心意思是：**Git 会识别出在您的本地分支中，哪些提交所包含的“代码变更”是独一无二的，并且在远端被强制更新后的新历史中，找不到与之“等效”的变更。**



假设我们在使用 `git fetch` 获取远程仓库的信息后，不是执行合并操作，而是执行变基操作。

获取远程仓库信息后的状态：

![image-20250927143710902](./images/Git%20new.assets/image-20250927143710902.png)



此时执行变基操作，我们将得到与**合并操作（你将相同的内容又合并了一次，生成了一个新的提交）**不同的结果，如图中所示。

![image-20250927143443440](./images/Git%20new.assets/image-20250927143443440.png)

要想上述方案有效，还需要对方在变基时确保 C4' 和 C4 是几乎一样的。

当远端的 C4' 提交内容与您本地的 C4 不完全相同时，Git 会将您本地的 C4 视为一个全新的、未在对方分支历史中出现过的提交。因此，Git 会尝试将它作为一个独立的变更重新应用到 `teamone/master` 的最新位置（即 C4' 之后）。

例如，如果您本地的 C4 提交是在 `app.js` 文件的第 10 行插入一个名为 `calculate_price()` 的新函数，而您的同事在远端进行变基时，对 C4' 做了微小的修改，比如在该函数上多加了一行注释。

当您执行 `git rebase` 时，Git 会尝试将您本地的 C4 提交所产生的补丁（即在第 10 行添加 `calculate_price()` 函数的变更）应用到同事已经变基过的 `teamone/master` 分支的最新代码快照上。

此时，Git 的补丁应用机制会发现，补丁所要修改的区域（`app.js` 的第 10 行）的当前内容与补丁生成时所基于的上下文（即 C1 提交时的文件状态）不匹配。Git 无法自动判断您的意图是应该用 C4 的函数体覆盖 C4' 的函数体，还是保留 C4' 中已有的注释并进行合并。

因为无法自动做出决策，Git 会暂停变基过程，并报告一个合并冲突，需要您手动介入来解决。



## 工具

### 贮藏与清理

有时，当你在项目的一部分上已经工作一段时间后，所有东西都进入了混乱的状态， 而这时你想要切换到另一个分支做一点别的事情。

问题是，你不想仅仅因为过会儿回到这一点而为做了一半的工作创建一次提交。 针对这个问题的答案是 `git stash` 命令。

贮藏（stash）会处理工作目录的脏的状态——即跟踪文件的修改与暂存的改动——然后将未完成的修改保存到一个栈上， 而你可以在任何时候重新应用这些改动（甚至在不同的分支上）。



#### 贮藏工作

为了演示贮藏，你需要进入项目并改动几个文件，然后可以暂存其中的一个改动。 如果运行 `git status`，可以看到有改动的状态：

```
$ git status
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

	modified:   index.html

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

	modified:   lib/simplegit.rb
```



现在想要切换分支，但是还不想要提交之前的工作；所以贮藏修改。 将新的贮藏推送到栈上，运行 `git stash` 或 `git stash push`：

```
$ git stash
Saved working directory and index state \
  "WIP on master: 049d078 added the index file"
HEAD is now at 049d078 added the index file
(To restore them type "git stash apply")
```

Git 会将两部分内容打包储藏起来，**已暂存的修改**（您已经使用 `git add` 命令放入暂存区的变更），**未暂存的修改**（您已经修改但尚未使用 `add` 添加到暂存区的变更）。



可以看到工作目录是干净的了：

```
$ git status
# On branch master
nothing to commit, working directory clean
```



此时，你可以切换分支并在其他地方工作；你的修改被存储在栈上。 要查看贮藏的东西，可以使用 `git stash list`：

```
$ git stash list
stash@{0}: WIP on master: 049d078 added the index file
stash@{1}: WIP on master: c264051 Revert "added file_size"
stash@{2}: WIP on master: 21d80a5 added number to log
```

在本例中，有两个之前**已经存在的贮藏**，所以你看到了三个不同的贮藏。



#### 应用贮藏

`git stash apply` 命令用于将贮藏的工作重新应用

```
$ git stash apply
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

	modified:   index.html
	modified:   lib/simplegit.rb

no changes added to commit (use "git add" and/or "git commit -a")
```

在此处，应用贮藏时有一个干净的工作目录，并且尝试将它应用在保存它时所在的分支。

在应用储藏时，可以应用在不干净的工作目录，也可以应用在其他分支中。

可以在一个分支上保存一个贮藏，切换到另一个分支，然后尝试重新应用这些修改。

当应用贮藏时工作目录中有**修改过或未提交的文件**，如果有任何东西不能干净地应用，Git 会产生合并冲突。



#### 应用时指定名称

如果想要应用其中一个更旧的贮藏，可以通过名字指定它：

```
$ git stash apply stash@{2}
```

如果不指定一个贮藏，Git 认为指定的是最近的贮藏。



当您运行 `git stash` 时，Git 会将两部分内容打包储藏起来，**已暂存的修改**（您已经使用 `git add` 命令放入暂存区的变更），**未暂存的修改**（您已经修改但尚未使用 `add` 添加到暂存区的变更）。

如果只使用 `git stash apply`，Git 会将上述两部分修改全部恢复到您的“工作目录”中，但所有文件变更都会变为“未暂存的修改”，即使它们在储藏前是已暂存状态。需要重新 `add`。

如果使用 `git stash apply --index`，它会将在储藏前**已暂存**的修改，重新应用为**已暂存**状态，在储藏前**未暂存**的修改，重新应用为**未暂存**状态。

```
$ git stash apply --index
On branch master
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

	modified:   index.html

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

	modified:   lib/simplegit.rb
```



应用选项只会尝试应用贮藏的工作——在堆栈上还有它。 可以运行 `git stash drop` 加上将要移除的贮藏的名字来移除它：

```
$ git stash list
stash@{0}: WIP on master: 049d078 added the index file
stash@{1}: WIP on master: c264051 Revert "added file_size"
stash@{2}: WIP on master: 21d80a5 added number to log
$ git stash drop stash@{0}
Dropped stash@{0} (364e91f3f268f0900bc3ee613f9f733e82aaed43)
```

如果不设置名字，则默认移除最近的贮藏。



#### 应用贮藏并移除

运行 `git stash pop` 会应用贮藏然后立即从栈上移除：

```
$ git stash pop
```

如果在应用的时候与当前工作目录中的文件产生了冲突，则不会自动移除，仍然需要使用 drop 手动移除。





#### 贮藏时留暂存区内容

`git stash` 命令会打包所有修改（暂存区 + 工作目录），默认情况下会将你的工作区和暂存区都恢复到干净的状态（即 `HEAD` 提交时的状态）。

如果使用 `--keep-index` 参数，就只会重置工作目录，保留已经通过 `git add` 添加到暂存区中的内容。

```
$ git status -s
M  index.html
 M lib/simplegit.rb

$ git stash --keep-index
Saved working directory and index state WIP on master: 1b65b17 added the index file
HEAD is now at 1b65b17 added the index file

$ git status -s
M  index.html
```



####  贮藏未跟踪文件

默认情况下，`git stash` 只会贮藏已修改和暂存的**已跟踪**文件。未跟踪（新增）的文件不会保存，任然存在工作目录中。

```
$ git status
On branch master
Untracked files:
  (use "git add <file>..." to include in what will be committed)
        test.txt

nothing added to commit but untracked files present (use "git add" to track)

$ git stash push
No local changes to save

$ git status
On branch master
Untracked files:
  (use "git add <file>..." to include in what will be committed)
        test.txt

nothing added to commit but untracked files present (use "git add" to track)
```



如果指定 `--include-untracked` 或 `-u` 选项，Git 也会贮藏任何未跟踪文件。

```
$ git status
On branch master
Untracked files:
      (use "git add <file>..." to include in what will be committed)
        test.txt

nothing added to commit but untracked files present (use "git add" to track)

$ git stash push -u
Saved working directory and index state WIP on master: d9e2d32 aa

$ git status
On branch master
nothing to commit, working tree clean
```



#### 贮藏所有文件

在贮藏中包含未跟踪的文件仍然不会包含明确**忽略**的文件.要额外包含忽略的文件，请使用 `--all` 或 `-a` 选项（包含 `-u` 的功能）。

```
$ git stash push -a
```



#### 创建分支并应用贮藏

**为你最近一次贮藏的修改创建一个全新的、独立的分支，并将这些修改恢复到这个新分支上。**

```
git stash branch <新分支名>
```



Git 首先会找到你执行 `git stash` 命令时所在的那个提交（commit）。每个贮藏 (`stash`) 都记录了它是在哪个提交的基础上创建的。

它会以上一步找到的那**原始提交**为起点，创建一个新的分支。

创建分支后，立即切换到这个新分支上。在这个新分支上，它会执行 `git stash apply`，并且智能地恢复暂存区（Staging Area）的状态，就像使用了 `--index` 选项一样。

如果上一步应用成功（由于是在原始提交上操作，所以通常不会有冲突），它会自动删除刚刚应用掉的那个贮藏。



#### 清理工作目录

对于工作目录中一些工作或文件，你想做的也许不是贮藏而是移除。 `git clean` 命令就是用来干这个的。

清理工作目录有一些常见的原因，比如说为了外部工具生成的东西， 或是为了运行一个干净的构建而移除之前构建的残留。

你需要谨慎地使用这个命令，因为它被设计为从工作目录中移除未被追踪的文件。 如果你改变主意了，你也不一定能找回来那些文件的内容。



一个更安全的选项是运行 `git stash --all` 来移除每一样东西并存放在栈中。

```
$ git stash --all
```



默认情况下，`git clean` 命令只会移除**没有忽略的未跟踪文件**。

```
$ git clean
```

准确来说，你需要加上 `-f` 参数表示“强制（force）”或“确定要移除”，或者将 Git 配置变量 `clean.requireForce` 显式设置为 `false`（默认为 `true` )。

`clean.requireForce`  为 `true` 时表示**“除非用户非常明确地使用 `-f` 或 `--force` 参数来表示‘我确定要删除’，否则不要执行 `git clean` 命令。”**

```
$ git clean -f
$ git config clean.requireForce false
```



使用 `git clean -f -d` 命令来**递归地进入目录清理未跟踪的文件（不包括被忽略的文件）**以及**空的子目录**。 `-f` 意味着“强制（force）”或“确定要移除”，使用它需要 Git 配置变量 `clean.requireForce` 没有显式设置为 `false`。

```
$ git clean -f -d
```



如果只是想要看看它会做什么，可以使用 `--dry-run` 或 `-n` 选项来运行命令， 这意味着“做一次演习然后告诉你 **将要** 移除什么”。

```
$ git clean -d -n
Would remove test.o
Would remove tmp/
```



任何与 `.gitignore` 或其他忽略文件中的模式匹配的文件都不会被移除。

如果你也想要**移除那些被忽略的文件**，例如为了做一次完全干净的构建而移除所有由构建生成的 `.o` 文件， 可以给 clean 命令增加一个 `-x` 选项。

```
$ git status -s
 M lib/simplegit.rb
?? build.TMP
?? tmp/

$ git clean -n -d
Would remove build.TMP
Would remove tmp/

$ git clean -n -d -x
Would remove build.TMP
Would remove test.o
Would remove tmp/
```

如果不知道 `git clean` 命令将会做什么，在将 `-n` 改为 `-f` 来真正做之前总是先用 `-n` 来运行它做双重检查。



另一个小心处理过程的方式是使用 `-i` 或 “interactive” 标记来运行它。这种方式下可以分别地检查每一个文件或者交互地指定删除的模式。

```
$ git clean -x -i
Would remove the following items:
  build.TMP  test.o
*** Commands ***
    1: clean                2: filter by pattern    3: select by numbers    4: ask each             5: quit
    6: help
What now>
```



## 命令参考

### switch

`git switch` 是一个相对较新的 Git 命令（在 Git 2.23 版本中引入），它的设计目标是**专门负责分支的切换和创建**。

在以前，这些功能都由 `git checkout` 命令承担，但 `git checkout` 功能过于庞杂（还能撤销文件修改），容易引起混淆。因此，Git 将其功能拆分，用 `git switch` 负责分支操作，`git restore` 负责文件恢复。



`git switch` 命令的核心功能

1. **切换到**一个已经存在的分支。
2. **创建并切换到**一个新的分支。



语法：

```
git switch [<options>] [<branch>]
```



#### 切换分支

最基本的用法，后面跟一个已经存在的分支名，用于切换到该分支。

```
git switch <branch> 
```

```
git switch main
```



#### -c

参数：

```
-c, --create <branch>
```



**创建（Create）**并切换到一个新的分支。这是最常用的参数之一。

```
git switch -c new-feature
```

创建一个名为 `new-feature` 的新分支，并立即切换过去。这等价于旧命令 `git checkout -b new-feature`。



#### -C

参数：

```
-C, --force-create <branch>
```



**强制创建（Force-Create）**并切换分支。如果分支已经存在，这个命令会先将该分支**重置（reset）**到当前 `HEAD` 指向的提交，然后再切换过去。

```
git switch -C existing-feature
```

如果 `existing-feature` 分支已存在，它会被重置并指向当前提交，然后切换过去。这是一个有风险的操作，因为它会丢弃掉原分支上独有的提交。



#### --guess

参数：

```
--guess
```



这是一个智能**猜测**功能（默认开启）。如果你尝试切换到一个本地不存在但远程仓库中恰好有一个同名分支（如 `origin/feature-x`），Git 会自动为你创建一个本地分支 `feature-x` 并设置它跟踪 `origin/feature-x`。

```
git switch --guess feature-x
```

如果本地没有 `feature-x` 但远程有 `origin/feature-x`，会自动执行 `git switch -c feature-x --track origin/feature-x`。



#### --discard-changes 

参数：

```
--discard-changes 
```

```
-f, --force
```

这两个参数的作用是完全等价的。它们都会强制切换分支，并丢弃所有本地的修改（包括已暂存和未暂存的）。



**丢弃本地修改**并强制切换分支。如果你当前工作区有未提交的修改，并且这些修改与你要切换到的分支有冲突，Git 默认会阻止你切换以防数据丢失。

使用此参数会强制 Git 丢弃这些本地修改，然后完成切换。**这是一个危险操作，请谨慎使用！**

```
git switch --discard-changes main
```

```
git switch -f main 
```



#### -d

参数：

```
-d, --detach
```



切换时不是指向一个分支，而是直接指向一个特定的提交（commit），HEAD 进入“**分离头指针（Detached HEAD）**”状态。

这通常用于查看历史代码状态，不建议在此状态下进行新的提交，因为这些提交不属于任何分支，容易丢失。

```
git switch --detach v1.0.1 
```

```
git switch --detach f83dee
```



#### -t

参数：

```
-t, --track
```



在创建新分支时，为其设置**跟踪（Track）**一个上游（通常是远程）分支。这使得 `git pull` 和 `git push` 可以省略分支名。

```
git switch -c feature-y -t origin/feature-y
```

创建本地分支 `feature-y` 并使其跟踪远程的 `origin/feature-y` 分支。



#### --orphan

参数：

```
--orphan <new-branch>
```



创建一个**孤儿（Orphan）**分支。这是一个全新的、没有任何历史提交记录的分支。它的第一个提交将成为根提交。

这在创建完全独立于项目主历史的分支时很有用（例如，`gh-pages` 分支用于存放网站文档）。

```
git switch --orphan project-docs
```

创建一个全新的 `project-docs` 分支，它与 `main` 或其他分支没有任何历史关联。



#### --ignore-other-worktrees

参数：

```
--ignore-other-worktrees
```



忽略其他**工作树（Worktrees）**的检查。Git 的 `worktree` 功能允许你将同一个仓库的不同分支检出到不同的目录。

默认情况下，`git switch` 会检查你要切换的分支是否已被其他工作树使用，以防冲突。此参数会跳过这个安全检查。



#### --overwrite-ignore

参数：

```
--overwrite-ignore
```

允许 Git 在切换分支时用跟踪的文件**覆盖（Overwrite）**被 `.gitignore` **忽略（Ignore）**的文件。

默认情况下，如果一个被忽略的文件与目标分支中的某个文件路径相同，切换会失败。



### worktree



### restore



### rebase



### reset







## 典型示例







## 常见问题

### 中文乱码

Git 默认会转义（escape）非 ASCII 字符的路径，导致中文显示为八进制编码。要解决这个问题，需要执行一条简单的配置命令，指定 Git 不用转义路径字符即可。



在命令行工具中输入并执行以下命令：

```
git config --global core.quotepath false
```

*这个命令会修改 Git 的全局配置（`--global`），将 `core.quotepath` 选项设置为 `false`。设置完成后，你再运行 `git status`，文件名应该就能正常显示为中文了。*