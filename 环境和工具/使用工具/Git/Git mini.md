# 新建项目

## 创建项目

```
git init
```



## 克隆项目

### 使用默认名称

```
git clone <url>
```

### 自定义项目名称

```
git clone <url> <newName>
```



# 快照基础

## 添加到暂存区

```
git add
```



## 查看文件状态

```
git status
```



## 查看文件差异

### 工作区与暂存区差异

```
git diff
```

### 最后提交与暂存区差异

```
git diff --staged
```

### 两个提交记录的差异

```
git diff <branch_A> <branch_B>
```



## 提交

### 进行一个提交

```
git commit
```

### 重置提交

```
git commit --amend
```

### 命令行传递提交信息

```
git commit -m "<提交信息>"
git commit --amend -m "<提交信息>"
```



## 撤销操作

恢复到一个提交快照，会改变工作区导致未提交的数据丢失，谨慎使用。

```
git reset --hard <commit_id>
```



## 移除文件

### 从暂存区中移除

只会从暂存区中移除文件，不会从工作目录（磁盘）中删除该文件

```
git rm --cached <fileName>
```



### 从工作区中移除

会将文件从暂存区和工作区（磁盘）中删除，会导致未提交的数据丢失，谨慎使用。

```
git rm <fileName>
```



## 移动文件

移动文件的位置，或者修改文件的名称

```
git mv <old_fileName> <new_fileName>
```



# 分支管理

## 创建分支

### 在当前创建

在**当前分支当前提交**，创建一个分支，创新新分支后`HEAD`指针任然**指向当前分支**。

```
git branch <new-branch>
```



### 在指定处创建

在**指定分支指定提交**中，创建一个新分支

`<commit-hash>`为指定提交的hash值

```
git branch <new-branch> <commit-hash>
```





## 切换分支

### 指定分支

切换到指定分支。

```
git checkout <branch_name>
```



### 指定提交

切换到指定分支的指定提交

```
git checkout <commit-hash>
```



### 创建后切换

`-b`参数，创建一个新分支后，`HEAD`指针指向（切换到）这个新分支

```
git checkout -b <new-branch>
```



## 查看分支

不加任何参数，列表显示当前所有分支

```
git branch
```



`-v`参数，列表显示当前所有分支，显示分支的详细信息

```
git branch -v
```



`-a`参数，列表显示当前所有分支，包括远程分支

```
git branch -a
```



`-va`参数，列表显示当前所有分支，包括远程分支，显示分支的详细信息

```
git branch -va
```



`--merged`，过滤这个列表中已经合并到当前分支的分支

```
git branch --merged
```



`--no-merged`，过滤这个列表中尚未合并到当前分支的分支

```
git branch --no-merged
```



## 跟踪分支

将当前分支（必须是本地分支）跟踪到一个远程分支上，该命令只能跟踪一个远程分支

```
git branch -u <remote/branch>
```



### 创建跟踪分支

快速创建一个本地分支，并且跟踪到一个远程分支，然后会切换到新建的本地分支，可能导致未提交的数据丢失

会创建一个与远程分支同名的本地分支，如果存在该名称的本地分支，则会出现错误提示

```
git checkout --track origin/master
```



-b参数，自定义远程分支名称

```
git checkout -b my_branch --track origin/master
```



# 远程仓库



## 1. 查看远程仓库

```
git remote -v <remote>
```

输出详细的信息

```
git remote -vv <remote>
```



## 2. 详细查看某个远程仓库

```
git remote show <remote>
```



## 3. 添加一个远程仓库

```
git remote add <newRemoteName> <remoteURL>
```



## 4. 移除或重命名远程仓库

移除一个远程仓库

```
git remote remove <remote>
```

重命名远程仓库名称

```
git remote rename <oldName> <newName>
```



## 5. 推送到远程仓库

将**当前分支**推送到**远程仓库（origin）**

```
git push <remote>
```

```
git push origin
```



将**指定本地分支（master）**推送到**远程仓库（origin）**

```
git push <远程仓库名称> <本地分支>
```

```
git push origin master
```



将**指定本地分支（new）**推送到**远程仓库（origin）**中的**指定分支（master）**

```
git push <远程仓库名称> <本地分支名称>:<远程分支名称>
```

```
git push origin new:master
```





## 6. 远程仓库拉取到本地

> 以下的所有操作**只会将远程仓库中的内容拉取到本地**，不会进行合并，如果**需要自动合并**，只需要**将命令中的`fetch`更换成`pull`**



将远程仓库（origin）中的所有内容拉取到本地

```
git fetch <remote>
```

```
git fetch origin
```



将**远程仓库（origin）**中的**远程分支（master）**拉取到本地。

如果没有与远程分支同名的本地分支（master）则会自动创建。

```
git fetch <remote> <branch>
```

```
git fetch origin master
```



将**远程仓库（origin）**中的**远程分支（master）**拉取到**指定本地分支（new）**上

如果指定的本地分支不存在，则会自动创建。

```
git fetch <remote> <remote/branch> <branch>
```

```
git fetch origin master:new
```

！！！注意：

Git 默认**不允许直接获取到当前检出的分支**，以防止在你正在工作时更改你的工作目录。

如果你想要更新 `new#1` 分支，你可以先**检出（切换）到另一个分支**，然后再执行 `fetch` 命令

```
git checkout master
git fetch origin master:new
```



## 7. 删除远程仓库中的分支

删除远程仓库（origin）中的远程分支（master）

```
git push <remote> --delete <remote/branch>
```

```
git push origin --delete master
```

