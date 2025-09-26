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

如果使用 `checkout` 命令直接检出到一个特定的提交、一个标签（`tag`）或一个远程分支的提交时，`HEAD` 会直接指向那个**提交对象**（该对象的哈希值）。此时 HEAD 不位于任何一个分支上，HEAD 处于**分离头状态 (Detached HEAD)**。在这种状态下，如果你进行新的提交，这个提交将不会属于任何分支。

在本例中，你仍然在 `master` 分支上。 因为 `git branch` 命令仅仅 **创建** 一个新分支，并不会自动切换到新分支中去。

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

在切换分支时，一定要注意你工作目录里的文件会被改变。 如果是切换到一个较旧的分支，你的工作目录会恢复到该分支最后一次提交时的样子。 **如果 Git 不能干净利落地完成这个任务，它将禁止切换分支。**

**工作目录中存在已修改、但未暂存的文件**

假设你在 `master` 分支上修改了 `main.py` 文件，但未将其添加到暂存区（未执行 `git add`）。此时，如果你尝试切换到 `dev` 分支，且 `dev` 分支上的 `main.py` 文件与你本地未修改的版本（即 `master` 分支上最后一次提交的版本）存在差异，Git 将拒绝切换。这是为了防止 `dev` 分支的文件覆盖你未暂存的修改，导致数据丢失。Git 会报错并中止操作以保护你的工作成果。

**工作目录中已修改的文件全部添加到了暂存区**

当你执行 `git add` 后，这些修改的“快照”已被安全地记录在暂存区（Staging Area）中。Git 认为这些工作已妥善保存，即使它们尚未提交。因此，在这种情况下，切换分支不会导致已暂存的修改丢失。

你会成功切换到新分支。执行 `git status` 时，你会发现这些已暂存的文件在新分支上依然处于暂存状态，等待你的后续提交。



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



## 常见问题

### 中文乱码

Git 默认会转义（escape）非 ASCII 字符的路径，导致中文显示为八进制编码。要解决这个问题，需要执行一条简单的配置命令，指定 Git 不用转义路径字符即可。



在命令行工具中输入并执行以下命令：

```
git config --global core.quotepath false
```

*这个命令会修改 Git 的全局配置（`--global`），将 `core.quotepath` 选项设置为 `false`。设置完成后，你再运行 `git status`，文件名应该就能正常显示为中文了。*