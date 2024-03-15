# .vimrc

vimrc文件是Vim编辑器的配置文件，用于设置Vim的各种参数和功能，例如将一个键映射到另一个键



Vim配置文件分为**系统配置文件**和**用户配置文件**两种：

- 系统配置文件位于Vim的安装目录，例如在Linux系统中，默认路径为`/etc/.vimrc`。
- 用户配置文件位于用户的主目录，例如在Linux系统中，路径为`~/.vimrc`。


注意，用户配置文件的优先级高于系统配置文件，通常只需要修改用户配置文件即可。



## 默认配置文件

**WebStorm**：

1. 安装IdeaVim插件。你可以在WebStorm的插件设置中搜索IdeaVim并安装。
2. IdeaVim会自动加载`%USERPROFILE%/_ideavimrc`文件作为配置文件。你可以编辑这个文件来添加你的Vim配置。



**Visual Studio 2022**：

1. 安装VsVim插件。你可以在Visual Studio的扩展管理器中搜索VsVim并安装。
2. VsVim会自动加载`%USERPROFILE%/_vimrc`文件作为配置文件。你可以编辑这个文件来添加你的Vim配置。



# 映射Esc键

在Vim中，你可以将其他键映射为`Esc`键，这样就可以避免频繁地移动手去按`Esc`键。

例如，许多人喜欢将`jj`或`jk`映射为`Esc`键，因为在英文中`jj`或`jk`的组合出现的频率很低，而且`j`键位于主键区，方便操作。

这样，每次你在插入模式下按`jj`，Vim就会返回到普通模式。

你可以在你的`.vimrc`文件中添加以下内容来实现这个映射：



用`jk`替换`Esc`键：

```vim
inoremap jj <Esc>
```



用`jk`替换`Esc`键：

```vim
inoremap jk <Esc>
```

