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



**Visutal Studio Code**

1. 安装Vim插件，在Visual Studio Code的扩展管理器中搜索Vim并安装。

![image-20240916104602200](./images/vim.assets/image-20240916104602200.png)

2. 按住`Ctrl+Shift+P`输入`vim.user`，打开用户设置JSON

![image-20240916104644039](./images/vim.assets/image-20240916104644039.png)

3. 开启vimrc配置文件，并指定配置文件的路径

   ```json
   {
       "vim.vimrc.enable": true,
       "vim.vimrc.path": "C:\\Users\\Xiaoshae\\_vimrc"
   }
   ```



# 映射Esc键



在Vim中，你可以将其他键映射为`Esc`键，这样就可以避免频繁地移动手去按`Esc`键。

例如，许多人喜欢将`jj`或`jk`映射为`Esc`键，因为在英文中`jj`或`jk`的组合出现的频率很低，而且`j`键位于主键区，方便操作。

这样，每次你在插入模式下按`jj`，Vim就会返回到普通模式。

你可以在你的`.vimrc`文件中添加以下内容来实现这个映射：



插入模式用`jk`替换`Esc`键：

```vim
inoremap jj <Esc>
```



插入模式用`jk`替换`Esc`键：

```vim
inoremap jk <Esc>
```



普通模式下用`jf`替换`Esc`键

```
nnoremap jf <Esc>
```



# 开启关闭高亮

命令模式键入，关闭高亮

```
noh
```

命令模式键入，开启高亮

```
set hlsearch
```



# 搜索

- `/`：这个命令会在文本中向**下**（也就是向前）搜索你输入的内容。

`n` 会跳转到下一个匹配项，`N` 会跳转到上一个匹配项。



- `?`：这个命令会在文本中向**上**（也就是向后）搜索你输入的内容。

`n` 会跳转到上一个匹配项，`N` 会跳转到下一个匹配项。



搜索的文本中包含特殊字符，如 `/` 或 `?`，需要在这些字符前面加上反斜杠 `\` 来进行转义。

例如：搜索 `/home/user`，应该输入 `\/home\/user`。



# 复制和粘贴

复制和粘贴仅限于普通模式



选择一个句子或更长的文本

1. **进入可视模式**：按 `v` 键进入可视模式。
2. **选择文本**：使用方向键（或 `h`、`j`、`k`、`l`）选择你想要删除的文本。这可以是一个单词，一个句子，甚至是一个段落。



删除：d

复制：y

粘贴：p（如果选中一段文本，再粘贴，则是替换）



`dw` 键删除当前单词。

`cw` 键删除当前单词，然后进入更改模式。



dd：删除当前行

yy：复制当前行

p：粘贴



100dd：从当前行开始删除100行

100yy：从当前行开始复制100行



.vimrc 

```
inoremap jj <Esc>

set expandtab
set shiftwidth=4
set tabstop=4

set number

highlight CursorLine ctermbg=236 guibg=#333333
set cursorline
```



.virc

```
set noautoindent
set nosmartindent
syntax off
```



/usr/bin/vi

```
#!/bin/bash
vim -S /root/.virc "$@"
```

