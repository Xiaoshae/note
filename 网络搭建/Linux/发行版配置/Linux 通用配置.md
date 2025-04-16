# Linux 通用配置



## 绕过登录

Linux 绕过登录以 root 用户进入 shell，需要对计算机或控制台进行物理访问（且文件系统未被加密），因为重新启动系统是该过程的一部分。



**更改 GRUB 引导参数**

重新启动 Linux 系统，当 GRUB 启动菜单出现时，突出显示包含您的发行版名称的行，然后按“**e**”键进入编辑启动参数模式。

![img](./images/Linux%20%E9%80%9A%E7%94%A8%E9%85%8D%E7%BD%AE.assets/reset-root-password01.jpg)

**注：Highlight the row and press the "e" key. 翻译为“选中该行并按“e”键。”**



找到以“linux”开头的行，并确保它包含**“rw”**而不是“ro”。如果没有，请更改它。然后将**“init=/bin/bash”**附加到该行末尾，因为最终版本应类似于下面所示的版本。

![img](./images/Linux%20%E9%80%9A%E7%94%A8%E9%85%8D%E7%BD%AE.assets/reset-root-password02.jpg)

在 GRUB 引导参数上下文中，“*ro*”和“*rw*”是指定在引导过程中如何挂载文件系统的选项：

- “**ro**”：这代表“只读”。使用时，文件系统以只读模式挂载。在启动过程中执行文件系统检查通常是许多 Linux 系统在初始引导过程中的默认设置。然后，在初始引导检查完成后，系统使用“*rw*”重新挂载文件系统以允许正常操作。
- “**rw**”：这代表“读写”。设置此参数后，文件系统将以读写模式挂载。这意味着系统既可以读取文件系统，也可以写入文件系统。这也是我们需要的选项，因为要重置 root 密码，我们必须设置一个新密码。这涉及写入文件系统上的某些文件，因此需要“*rw*”。



**"init=/bin/bash"** 参数告诉系统以 Bash shell 作为初始进程来启动，而不是通常的 init 系统，因此，可以无需登录即可立即访问 root shell。

现在按**”Ctrl+x”**开始启动过程。



系统将以单用户模式启动，您最终将得到一个带有登录 root 帐户的 Bash shell。

![img](./images/Linux%20%E9%80%9A%E7%94%A8%E9%85%8D%E7%BD%AE.assets/reset-root-password04.jpg)

`save`：强制将缓存数据写入磁盘

`reboot -f`：强制重启

`poweroff -f`：强制关机



### 重设密码

要更新root用户的密码，我们只需要执行 `passwd` 命令，然后建立一个新的密码。

![img](./images/Linux%20%E9%80%9A%E7%94%A8%E9%85%8D%E7%BD%AE.assets/reset-root-password05.jpg)



