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
