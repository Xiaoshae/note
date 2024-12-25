# AAA

## 定义

AAA（Authentication Authorization Accounting）是一种提供认证、授权和计费的技术。

- 认证（Authentication）：验证用户是否可以获得访问权，确定哪些用户可以访问网络。
- 授权（Authorization）：授权用户可以使用哪些服务。
- 计费（Accounting）：记录用户使用网络资源的情况。



提供对用户进行认证、授权和计费三种安全功能。

AAA一般采用“客户端—服务器”结构。这种结构既具有良好的可扩展性，又便于用户信息的集中管理。

![image-20241225085010156](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/image-20241225085010156.png)

NAS 设备指的是 **Network Access Server（网络接入服务器）**





## 基于域的用户管理

NAS设备对用户的管理是基于域的，每个用户都属于一个域，一个域是由属于同一个域的用户构成的群体。简单地说，用户属于哪个域就使用哪个域下的AAA配置信息。

域统一管理AAA方案、服务器模板和授权等配置信息：

- AAA方案：分为认证方案、授权方案和计费方案，用来定义认证、授权和计费的方法及每种方法的生效顺序。
    - 如果使用本地认证或授权，需要配置本地用户的相关信息。
- 服务器模板：用来配置认证、授权或计费使用的服务器。配置服务器授权时，用户从服务器和域下获取授权信息。
- 域下的授权信息：域下还可以配置授权信息。

![img](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/fig_dc_cfg_aaa_602202_01.png)

### 用户所属的域

用户所属的域是由用户登录到NAS设备时提供的用户名决定的，当用户名中没有携带域名或者携带的域名在NAS设备上未配置时，NAS设备无法确认用户所属的域，此时，NAS设备根据用户的类型将用户加入到默认域中。

![img](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/fig_dc_cfg_aaa_602201.png)

为了提供更为精细且有差异化的认证、授权、计费服务，AAA将用户划分为管理员用户和接入用户两种类型。NAS设备存在两个全局默认域：全局默认管理域default_admin和全局默认普通域default，分别作为管理员用户和接入用户的全局默认域，两个全局默认域下的缺省配置也不同。

- 两个全局默认域缺省都绑定了名称为default的计费方案，修改该计费方案会同时影响这两个域的配置。
- 两个全局默认域均不能删除，只能修改。



全局默认域

![image-20241225102627927](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/image-20241225102627927.png)

用户也可以根据实际需求，灵活定义全局默认域。自定义的全局默认域可以同时被配置成全局默认普通域和全局默认管理域。

通过命令**display aaa configuration**，可以查看设备当前配置的全局默认普通域和全局默认管理域。显示如下：

```
<Huawei> display aaa configuration
  Domain Name Delimiter            : @
  Domainname parse direction       : Left to right
  Domainname location              : After-delimiter
  Administrator user default domain: default_admin    //全局默认管理域
  Normal user default domain       : default    //全局默认普通域
```





## 认证

### 认证类型

- 不认证：对用户非常信任，不对其进行合法性检查，一般情况下不采用这种方式。

- 本地认证：设备作为认证服务器，将用户信息配置在设备上。本地认证的优点是速度快，可以为运营降低成本，缺点是存储信息量受设备硬件条件限制。
- 远端认证：将用户信息（包括本地用户的用户名、密码和各种属性）配置在认证服务器上。AAA支持 RADIUS 和 HWTACACS 服务器。



### 认证顺序

认证方案中可以指定一种或者多种认证方法：按照配置顺序，NAS设备首先选择第一种认证方法，当前面的认证方法无响应时，后面的认证方法才会被启用；直到某种认证方法有响应或者所有的认证方法遍历完成后均无响应（均无响应时用户认证失败）时，用户身份认证过程将被停止。

仅前一种方法无响应时，NAS设备才尝试使用下一个认证方法。如果某种认证方法回应认证失败，则意味着AAA服务器拒绝用户接入，用户身份认证过程将被停止，并且不会尝试后面的认证方法。



## 授权

AAA支持以下授权方式：

- 不授权：不对用户进行授权。
- 本地授权：设备作为授权服务器，根据设备上配置的用户信息进行授权。
- 远程授权：由远程服务器对用户进行授权。
    - HWTACACS 授权：由HWTACACS服务器对用户进行授权。
    - RADIUS 授权：RADIUS协议的认证和授权是绑定在一起的，不能单独使用RADIUS进行授权。
- if-authenticated授权：用户认证通过，则授权通过，否则授权不通过。适用于用户必须认证且认证过程与授权过程可分离的场景。



### 授权顺序

授权方案中可以指定一种或者多种授权方法。指定多种授权方法时，配置顺序决定了每种授权方法生效的顺序，配置在前的授权方法优先生效。当前面的授权方法无响应时，后面的授权方法才会启用。如果前面的授权方法回应授权失败，表示AAA服务器拒绝为用户提供服务。此时，授权结束，后面的授权方法不会被启用。



### 授权信息

授权信息分为两类：服务器下发的授权信息和域下的授权信息。用户从何处获取授权与授权方案中配置的授权方法有关。

- 授权方法为本地授权时，用户从域下获取授权信息。
- 授权方法为服务器授权时，用户从服务器和域下获取授权信息。域下配置的授权信息比服务器下发的授权信息优先级低，如果两者的授权信息冲突，则服务器下发的授权优先生效；如果两者的授权信息不冲突，则两者的授权信息同时生效。这样处理可以通过域管理进行灵活授权，而不必受限于服务器提供的授权。



![img](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/fig_dc_cfg_aaa_602204.png)





## 计费

AAA支持以下计费方式：

- 不计费：不对用户计费。
- 远端计费：支持通过远程服务器进行远端计费。
    - RADIUS 计费：由 RADIUS 服务器对用户进行计费。
    - HWTACACS 计费：由 HWTACACS 服务器对用户进行计费。



## 本地方式进行认证和授权

在本地方式进行认证和授权中，用户信息（包括本地用户的用户名、密码和各种属性）都配置在设备上。本地方式进行认证和授权的优点是速度快，可以降低运营成本，缺点是存储信息量受设备硬件条件限制。



### 配置流程

![image-20241225102803475](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/image-20241225102803475.png)



配置本地服务器，需要在设备上配置用户的认证和授权信息，包括配置本地用户和配置本地授权两个步骤。

### 配置本地用户

配置本地用户时，可以配置本地用户允许建立的连接数目、本地用户级别、闲置切断时间以及本地用户上线时间等功能，同时支持本地用户修改密码功能。

- 为充分保证设备安全，请用户**不要关闭密码复杂度检查功能**，并定期修改密码。

- 更改本地账号的权限（密码、接入类型、FTP目录、级别等）后，**已经在线的用户权限不会被更改**，新上线的用户则以新的权限为准。

- 本地用户的接入类型分为以下两类：

    - 管理类：包括ftp、http、ssh、telnet、x25-pad和terminal。
    - 普通类：包括8021x、bind、ppp、sslvpn和web。

- 登录方式为Telnet和FTP时存在安全风险，建议使用STelnet和SFTP，此时，用户的接入类型配置为SSH。

    缺省情况下，HTTP采用随机生成的自签名证书支持HTTPS。由于自签名证书存在安全风险，因此建议用户替换为官方授信的数字证书。



**操作步骤**

1. 执行命令 **system-view**，进入系统视图。
2. 执行命令 **aaa** ，进入AAA视图。
3. 创建本地用户。

![image-20241225103209091](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/image-20241225103209091.png)

4. （可选）配置用户级别、所属用户组、接入时间段、闲置切断功能及可建立的连接数目。

![image-20241225103238574](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/image-20241225103238574.png)

5. （可选）配置本地用户安全性。

![image-20241225103305836](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/image-20241225103305836.png)

6. （可选）本地用户访问权限相关配置。

![image-20241225103334544](./images/%E5%8D%8E%E4%B8%BA%20AAA.assets/image-20241225103334544.png)

7. （可选）修改本地用户登录密码。

| 步骤                 | 命令                       | 说明 |
| -------------------- | -------------------------- | ---- |
| 返回用户视图         | return                     | -    |
| 修改本地用户登录密码 | local-user change-password |      |



#### 本地用户

1. 密码复杂度检查

使能对密码进行复杂度检查功能（如果需要）。默认情况下，设备已经启用了密码复杂度检查。若要启用或调整此功能，可以使用 `user-password complexity-check` 命令。

2. 用户名与密码设定

使用 `local-user user-name password` 或 `local-user user-name password { cipher | irreversible-cipher } password` 来创建本地用户名和密码。建议通过交互式方式输入密码以确保安全性。对于带有域名分隔符的用户名，解析规则会自动应用于确定纯用户名和域名。

3. 接入类型配置

通过 `local-user user-name service-type` 指定允许的接入类型，如802.1X, FTP, HTTP, PPP, SSH等。默认所有接入类型都是关闭的。为Portal用户配置的接入类型应为web。

4. 固定IP地址分配（可选）

- 为本地用户分配固定IP地址可以通过 `local-user user-name bind-ip ip-address` 实现。默认情况下，没有为用户分配固定的IP地址。

#### 配置用户属性

1. 用户级别

设置用户的权限级别使用 `local-user user-name privilege level level`。默认级别为0级。

2. 用户组归属

将用户添加到特定用户组通过 `local-user user-name user-group group-name` 完成。默认用户不属于任何用户组。

3. 接入时间段

限制用户只能在特定时间内接入网络，使用 `local-user user-name time-range time-name`。默认情况下，用户可以在任意时间接入。

4. 闲置切断

对于普通用户，使用 `local-user user-name idle-cut`；对于管理用户，使用 `local-user user-name idle-timeout minutes [ seconds ]` 来设置闲置切断时间。这将导致用户在一段时间不活动后自动下线。

5. 连接数目限制

限制用户可建立的最大连接数使用 `local-user user-name access-limit max-number`。默认不限制连接数。

#### 安全性配置

1. 账户锁定

启用本地账户锁定功能，并设置重试间隔、连续认证失败次数限制以及账户锁定时长，使用 `local-aaa-user wrong-password retry-interval retry-time block-time`。

2. 锁定期间访问

允许在账号锁定期间使用指定IP地址访问网络，使用 `aaa-quiet administrator except-list { ipv4-address | ipv6-address }`。

3. 密码策略

对于本地接入用户和管理员，分别使用 `local-aaa-user password policy access-user` 和 `local-aaa-user password policy administrator` 来启用密码策略，并进一步配置密码历史记录数量、过期提醒、初始密码提醒和密码过期时间。

#### 访问权限相关配置

1. FTP目录

如果用户的接入类型包括FTP，则必须配置允许访问的FTP目录，使用 `local-user user-name ftp-directory directory`。此外，用户的级别不能低于管理级。

2. 用户状态

控制用户是否处于激活或阻塞状态，使用 `local-user user-name state { active | block }`。激活态接收认证请求，而阻塞态拒绝请求。

3. 账号有效期

设定本地账号的有效期限，使用 `local-user user-name expire-date expire-date`。默认情况下，账号是永久有效的。

4. 修改密码

若要修改现有用户的登录密码，返回用户视图后，执行 `local-user change-password`。





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



# 配置通过Console口登录Console用户界面的用户级别

操作步骤

1. 执行命令**system-view**，进入系统视图。
2. 执行命令**user-interface console 0**，进入Console用户界面视图。
3. 执行命令**user privilege level level**，配置Console用户界面的用户级别。
    - 缺省情况下，Console 口用户界面的用户级别为15。
    - 如果用户界面下配置的命令级别访问权限与用户名本身对应的操作权限冲突，以用户名本身对应的级别为准。
    - 如果对用户采用Password认证，登录到设备的用户所能访问的命令级别由登录时的Console用户界面的级别决定。
    - 如果对用户采用AAA认证，登录到设备的用户所能访问的命令级别由AAA配置信息中本地用户的级别决定。
    - 缺省情况下，AAA本地用户的级别为0。在AAA视图下，执行 local-user user-name privilege level level 命令可以修改AAA配置信息中本地用户的级别。
