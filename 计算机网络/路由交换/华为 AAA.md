# AAA

## AAA本地认证简介

AAA本地认证可以对用户进行身份认证，用户输入正确的用户名和密码才可以成功登录设备。AAA本地认证将用户信息配置在设备上，不需要网络中部署其他认证服务器，速度快并且为运营降低了成本，但存储信息量受设备硬件条件限制。



企业希望管理员能简单方便并且安全地远程管理设备，可以配置管理员通过Telnet登录设备时：

1. 管理员输入正确的用户名和密码才能通过Telnet登录设备。
2. 管理员通过Telnet登录设备后，可以执行命令级别为0～3的所有命令行。



配置用户通过Telnet登录设备的身份认证组网图（AAA本地认证）

![img](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/xhgahdsgnsadownload.png)

**配置思路**

1. 使能Telnet服务。
2. 配置用户通过Telnet登录的认证方式为AAA。
3. 配置AAA本地认证：创建本地用户、指定用户的接入类型为Telnet、配置用户级别为15级。



1. 配置接口和IP地址

    ```
    <HUAWEI> system-view
    [HUAWEI] sysname Switch
    [Switch] vlan batch 10
    [Switch] interface vlanif 10
    [Switch-Vlanif10] ip address 10.1.2.10 24
    [Switch-Vlanif10] quit
    [Switch] interface gigabitethernet0/0/1
    [Switch-GigabitEthernet0/0/1] port link-type access
    [Switch-GigabitEthernet0/0/1] port default vlan 10
    [Switch-GigabitEthernet0/0/1] quit
    ```

    

2. 使能Telnet服务器功能

    ```
    [Switch] telnet server enable
    [Switch] telnet server-source -i vlanif 10   //配置服务器端的源接口为10.1.1.1对应的接口，假设该接口为Vlanif 10。
    ```

    

3. 配置VTY用户界面的验证方式为AAA

    ```
    [Switch] user-interface maximum-vty 15  //配置VTY用户界面的登录用户最大数目为15（该数目在不同版本和不同形态间有差异，具体以设备为准），缺省情况下Telnet用户最大数目为5
    [Switch] user-interface vty 0 14  //进入0～14的VTY用户界面视图
    [Switch-ui-vty0-14] authentication-mode aaa  //配置VTY用户界面的验证方式为AAA
    [Switch-ui-vty0-14] protocol inbound telnet  //配置VTY用户界面支持的协议为Telnet，V200R006及之前版本缺省使用的协议为Telnet协议，可以不配置该项；V200R007及之后版本缺省使用的协议为SSH协议，必须配置。
    [Switch-ui-vty0-14] quit
    ```

    

4. 配置AAA本地认证

    ```
    [Switch] aaa
    
    # 创建本地用户user1并配置密码，由于配置文件中密码以密文显示，建议记住该密码，否则需要重新执行该命令覆盖配置（该命令在
    [Switch-aaa] local-user user1 password irreversible-cipher YsHsjx_202206  
    V200R002及之前版本为local-user user-name password cipher password）
    
    # 配置本地用户user1的接入类型为Telnet，该用户只能使用Telnet方式登录（缺省情况下，V200R007之前版本允许用户使用所有接入类型，V200R007及后续版本设备对用户关闭所有接入类型）
    [Switch-aaa] local-user user1 service-type telnet
    
    # 配置本地用户user1的用户级别为15，该用户登录后可以执行等于或低于3级的命令
    [Switch-aaa] local-user user1 privilege level 15
    Warning: This operation may affect online users, are you sure to change the user privilege level ?[Y/N]y
    
    [Switch-aaa] quit
    ```

    管理员输入的用户名不包含域名时，使用默认管理域default_admin认证，default_admin使用缺省的认证方案default和计费方案default。

    - 认证方案default：采用本地认证方式。
    - 计费方案default：采用不计费方式。

    

5. 验证配置结果

    管理员在PC上单击 “运行” ->输入 “cmd”，进入Windows的命令行提示符界面，执行telnet命令，并输入用户名user1和密码YsHsjx_202206，通过Telnet方式登录设备成功。

    ```
    C:\Documents and Settings\Administrator> telnet 10.1.2.10
    Username:user1
    Password:***********
    <Switch>//管理员登录设备成功
    ```

