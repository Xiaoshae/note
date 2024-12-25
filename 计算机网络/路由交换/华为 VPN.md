# 华为 VPN

## GRE

通用路由封装协议GRE（Generic Routing Encapsulation）可以对某些**网络层协议（如IPX、ATM、IPv6、AppleTalk等）的数据报文进行封装**，使这些被封装的数据报文能够在另一个网络层协议（如IPv4）中传输。

GRE提供了将一种协议的报文封装在另一种协议报文中的机制，是一种**三层隧道封装技术**，使报文可以通过GRE隧道透明的传输，解决异种网络的传输问题。



### 配置Tunnel接口

GRE隧道是通过隧道两端的Tunnel接口建立的，所以需要在**隧道两端的设备**上**分别配置Tunnel接口**。对于GRE的Tunnel接口，需要指定其**协议类型为GRE**、**源地址或源接口**、**目的地址和Tunnel接口IP地址**。

- Tunnel的源地址：配置报文传输协议中的源地址。当配置地址类型时，直接作为源地址使用。当配置类型为源接口时，取该接口的IP地址作为源地址使用。
- Tunnel的目的地址：配置报文传输协议中的目的地址。
- Tunnel接口IP地址：为了在Tunnel接口上启用动态路由协议，或使用静态路由协议发布Tunnel接口，需要为Tunnel接口分配IP地址。Tunnel接口的IP地址可以不是公网地址，甚至可以借用其他接口的IP地址以节约IP地址。但是当Tunnel接口借用IP地址后，该地址不能直接通过tunnel口互通，因此在借用IP地址情况下，必须配置静态路由或路由协议先实现借用地址的互通性，才能实现Tunnel的互通。



#### 操作步骤

1. 执行命令 **system-view**，进入系统视图。

2. 执行命令 **interface tunnel interface-number**，创建Tunnel接口，并进入Tunnel接口视图。

3. 执行命令 **tunnel-protocol gre**，配置Tunnel接口的隧道协议为GRE。

4. （可选）执行命令 **gre key** { plain key-number | [ cipher ] plain-cipher-text }，设置GRE隧道的识别关键字。

    - 当设备之间**只有一条物理链路**且**源地址和目的地址只能取一个时**，由于只能配置一个源地址和目的地址相同的Tunnel接口，因此不能承载不同的业务流量。
    - 为了解决上述问题，系统支持配置两条或两条以上源地址和目的地址相同的Tunnel接口，通过命令**gre key配置不同的GRE Key字段来区分这些GRE隧道**，从而可以承载不同的业务流量。
    - 若将多条GRE隧道配置为相同的源地址和目的地址，**建议先配置gre key，否则会提示隧道配置冲突**。

5. 执行命令 **source** { source-ip-address | interface-type interface-number }，配置Tunnel的源地址或源接口。

    - 配置Tunnel的源接口时，有如下注意事项：
        - Tunnel的源接口不能指定为自身GRE隧道的Tunnel接口，但可以指定为其他隧道的Tunnel接口。
        - Tunnel的源地址可以配置为VRRP备份组的虚地址。
        - Bridge-if接口不可配置为Tunnel的源接口。

6. 执行命令 **destination** [ vpn-instance vpn-instance-name ] dest-ip-address，配置Tunnel的目的地址。

    - 如果CE设备通过GRE隧道连接到PE，则PE上配置Tunnel的目的地址时，需要指定VPN实例，将Tunnel接口加入私网路由表。

7. （可选）执行命令 **tunnel** route-via interface-type interface-number { mandatory | preferred }，指定**GRE隧道的路由出接口**。

    - 缺省情况下，**未指定GRE隧道的路由出接口**。
    - GRE隧道封装后的报文将查找路由转发表进行转发，如果GRE隧道的目的地址存在等价路由且存在多条目的地址相同的GRE隧道，则这些GRE隧道封装的报文将以负载分担进行转发。
    - 此时某些GRE隧道封装后报文的实际出接口可能是另一个隧道的源IP接口。如果该链路上下一跳设备配置了URPF（Unicast Reverse Path Forwarding）检测，则以报文的源IP做为目的IP，在转发表中查找源IP对应的接口是否与入接口匹配，因此会发现报文源IP对应的接口与报文的入接口不一致，则认为报文非法并丢弃。
    - 为了解决这个问题，可以配置 **tunnel route-via** 命令指定GRE隧道路由出接口，使报文严格或优先从隧道的源IP地址所在的出接口转发。
    - 通过设置**mandatory**和**preferred**参数选择下列两种模式：
        - **mandatory**：严格按照指定的出接口转发流量，如果GRE隧道目的地址的路由出接口不包含指定的出接口时，隧道接口状态为Down，不进行流量转发。
        - **preferred**：优先按照指定的出接口转发流量，如果GRE隧道目的地址的路由出接口不包含指定的出接口时，则可以选择其他接口转发，隧道接口状态为Up。

8. （可选）执行命令**mtu** mtu，配置Tunnel接口的MTU。

    - 缺省情况下，**Tunnel接口的MTU值为1500**。
    - 如果改变Tunnel接口最大传输单元MTU，需要先对接口执行 **shutdown** 命令，再执行 **undo shutdown** 命令将接口重启，以保证设置的MTU生效。

9. （可选）执行命令 **description** text，配置接口的描述信息。

    - 缺省情况下，Tunnel接口默认描述信息为“HUAWEI, AR Series, Tunnel interface-number Interface”。
    - 例如，缺省情况下，Tunnel0/0/1接口默认描述信息为“HUAWEI, AR Series, Tunnel0/0/1 Interface”。

10. 指定Tunnel接口的IP地址，选择如下方法之一：

    - 创建IP地址

        - 若是采用GRE隧道实现IPv4协议的互通，必须在Tunnel接口下配置IPv4地址：

            执行命令 **ip address** *ip-address* { *mask* | *mask-length* } [ **sub** ]，配置Tunnel接口的IPv4地址。

        - 若是采用GRE隧道实现IPv6协议的互通，必须在Tunnel接口下配置IPv6地址：

            执行命令 **ipv6 address**  { *ipv6-address prefix-length* | *ipv6-address*/*prefix-length* }，配置Tunnel接口的IPv6地址。

            - 配置接口的IPv6地址前，需要在系统视图下使用命令**ipv6**使能IPv6报文转发功能，并在该接口下使用命令**ipv6 enable**使能接口的IPv6功能。

    - 借用IP地址

        - 执行命令 **ip address unnumbered** interface interface-type interface-number，配置Tunnel接口借用IP地址。
            - **部分设备不支持借用IPv6地址。**



### 配置Tunnel接口的路由

在保证本端设备和远端设备在骨干网上路由互通的基础上，本端设备和远端设备上必须存在经过Tunnel接口转发的路由，这样，需要进行GRE封装的报文才能正确转发。经过Tunnel接口转发的路由可以是静态路由，也可以是动态路由。

- 配置**静态路由时**，**源端设备和目的端设备都需要配置**：此路由**目的地址是未进行GRE封装的报文的原始目的地址**（Router_2的GE2/0/0所在的网段地址），**出接口是本端Tunnel接口（Router_1的Tunnel0/0/1接口）**。
- 配置**动态路由协议**时，在**Tunnel接口和与X网络协议**相连的接口上都要使用该动态路由协议。
    - 例如，在图1中，如果使用动态路由协议配置Tunnel接口的路由，则Tunnel接口和接入X网络协议的GE2/0/0接口上都需要配置动态路由协议，并且路由表中去往Router_2的GE2/0/0网段的出接口是Tunnel0/0/1。
    - 实际配置时，Tunnel接口路由和骨干网的路由需要采用**不同类型的路由协议**或者**同类型协议的不同进程**，避免用户报文通过物理接口转发，而不是通过Tunnel接口转发。
    - 当在Tunnel接口使用动态路由并使能路由引入功能时，请将通往目的地址的路由配置为动态路由或是32位主机路由实现互通，避免通往目的地址的路由发布到Tunnel接口路由上，导致隧道震荡。



配置GRE动态路由协议组网图

![img](./images/%E5%8D%8E%E4%B8%BA%20VPN.assets/fig_dc_cfg_gre_000701ar.png)

1. 执行命令system-view，进入系统视图。
2. 配置经过Tunnel接口的路由，选择如下方法之一：
    - 执行命令 **ip route-static** ip-address { mask | mask-length } { nexthop-address | tunnel interface-number [ nexthop-address ] } [ description text ]，配置静态路由。
    - 配置动态路由。可以使用IGP或EGP，包括OSPF、RIP等路由协议，此处不再详述其配置方法。有关动态路由的配置，请参见 《配置指南 - IP路由》
    - 若是采用GRE隧道实现IPv6协议的互通，必须在Tunnel接口、与IPv6协议相连的物理接口上配置IPv6的路由协议。





### 配置GRE通过静态路由实现IPv4协议互通示例

RouterA、RouterB、RouterC使用OSPF协议路由实现公网互通。在PC1和PC2上运行IPv4私网协议，现需要PC1和PC2通过公网实现IPv4私网互通。

其中PC1和PC2上分别指定RouterA和RouterC为自己的缺省网关。



**配置GRE使用静态路由组网图**

![img](./images/%E5%8D%8E%E4%B8%BA%20VPN.assets/fig_dc_cfg_gre_002101.png)

要实现PC1和PC2通过公网互通。需要在RouterA和RouterC之间建立直连链路，部署GRE隧道，通过静态路由指定到达对端的报文通过Tunnel接口转发，PC1和PC2就可以互相通信了。

配置GRE通过静态路由实现IPv4协议互通的思路如下：

1. 所有设备之间运行OSPF路由协议实现设备间路由互通。
2. 在RouterA和RouterC上创建Tunnel接口，创建GRE隧道，并在RouterA和RouterC上配置经过Tunnel接口的静态路由，使PC1和PC2之间的流量通过GRE隧道传输，实现PC1和PC2互通。



#### 操作步骤

1. 配置各物理接口的IP地址

    \# 配置RouterA。

    ```
    <Huawei> system-view
    [Huawei] sysname RouterA
    [RouterA] interface gigabitethernet 1/0/0
    [RouterA-GigabitEthernet1/0/0] ip address 20.1.1.1 255.255.255.0
    [RouterA-GigabitEthernet1/0/0] quit
    [RouterA] interface gigabitethernet 2/0/0
    [RouterA-GigabitEthernet2/0/0] ip address 10.1.1.2 255.255.255.0
    [RouterA-GigabitEthernet2/0/0] quit
    ```

    \# 配置RouterB。

    ```
    <Huawei> system-view
    [Huawei] sysname RouterB
    [RouterB] interface gigabitethernet 1/0/0
    [RouterB-GigabitEthernet1/0/0] ip address 20.1.1.2 255.255.255.0
    [RouterB-GigabitEthernet1/0/0] quit
    [RouterB] interface gigabitethernet 2/0/0
    [RouterB-GigabitEthernet2/0/0] ip address 30.1.1.1 255.255.255.0
    [RouterB-GigabitEthernet2/0/0] quit
    ```

    \# 配置RouterC。

    ```
    <Huawei> system-view
    [Huawei] sysname RouterC
    [RouterC] interface gigabitethernet 1/0/0
    [RouterC-GigabitEthernet1/0/0] ip address 30.1.1.2 255.255.255.0
    [RouterC-GigabitEthernet1/0/0] quit
    [RouterC] interface gigabitethernet 2/0/0
    [RouterC-GigabitEthernet2/0/0] ip address 10.2.1.2 255.255.255.0
    [RouterC-GigabitEthernet2/0/0] quit
    ```



2. 配置设备间使用OSPF路由

    \# 配置RouterA。

    ```
    [RouterA] ospf 1
    [RouterA-ospf-1] area 0
    [RouterA-ospf-1-area-0.0.0.0] network 20.1.1.0 0.0.0.255
    [RouterA-ospf-1-area-0.0.0.0] quit
    [RouterA-ospf-1] quit
    ```

    \# 配置RouterB。

    ```
    [RouterB] ospf 1
    [RouterB-ospf-1] area 0
    [RouterB-ospf-1-area-0.0.0.0] network 20.1.1.0 0.0.0.255
    [RouterB-ospf-1-area-0.0.0.0] network 30.1.1.0 0.0.0.255
    [RouterB-ospf-1-area-0.0.0.0] quit
    [RouterB-ospf-1] quit
    ```

    \# 配置RouterC。

    ```
    [RouterC] ospf 1
    [RouterC-ospf-1] area 0
    [RouterC-ospf-1-area-0.0.0.0] network 30.1.1.0 0.0.0.255
    [RouterC-ospf-1-area-0.0.0.0] quit
    [RouterC-ospf-1] quit
    ```

    \# 配置完成后，在RouterA和RouterC上执行**display ip routing-table**命令，可以看到他们能够学到去往对端接口网段地址的OSPF路由。

    \# 以RouterA的显示为例。

    ```
    [RouterA] display ip routing-table protocol ospf
    <keyword conref="../commonterms/commonterms.xml#commonterms/route-flags"></keyword>                                          
    ------------------------------------------------------------------------------       
    Public routing table : OSPF                                                          
             Destinations : 1        Routes : 1                                          
                                                                                         
    OSPF routing table status : <Active>                                                 
             Destinations : 1        Routes : 1                                          
                                                                                         
    Destination/Mask    Proto   Pre  Cost      Flags NextHop         Interface           
                                                                                         
           30.1.1.0/24  OSPF    10   2           D   20.1.1.2        GigabitEthernet1/0/0
                                                                                         
    OSPF routing table status : <Inactive>                                               
             Destinations : 0        Routes : 0                                          
                                                                                         
    ```



3. 配置Tunnel接口

    \# 配置RouterA。

    ```
    [RouterA] interface tunnel 0/0/1
    [RouterA-Tunnel0/0/1] tunnel-protocol gre
    [RouterA-Tunnel0/0/1] ip address 10.3.1.1 255.255.255.0
    [RouterA-Tunnel0/0/1] source 20.1.1.1
    [RouterA-Tunnel0/0/1] destination 30.1.1.2
    [RouterA-Tunnel0/0/1] quit
    ```

    \# 配置RouterC。

    ```
    [RouterC] interface tunnel 0/0/1
    [RouterC-Tunnel0/0/1] tunnel-protocol gre
    [RouterC-Tunnel0/0/1] ip address 10.3.1.2 255.255.255.0
    [RouterC-Tunnel0/0/1] source 30.1.1.2
    [RouterC-Tunnel0/0/1] destination 20.1.1.1
    [RouterC-Tunnel0/0/1] quit
    ```

    \# 配置完成后，Tunnel接口状态变为Up，Tunnel接口之间可以Ping通，直连隧道建立。

    \# 以RouterA的显示为例：

    ```
    [RouterA] ping -a 10.3.1.1 10.3.1.2
      PING 10.3.1.2: 56  data bytes, press CTRL_C to break        
        Reply from 10.3.1.2: bytes=56 Sequence=1 ttl=255 time=1 ms
        Reply from 10.3.1.2: bytes=56 Sequence=2 ttl=255 time=1 ms
        Reply from 10.3.1.2: bytes=56 Sequence=3 ttl=255 time=1 ms
        Reply from 10.3.1.2: bytes=56 Sequence=4 ttl=255 time=1 ms
        Reply from 10.3.1.2: bytes=56 Sequence=5 ttl=255 time=1 ms
                                                                  
      --- 10.3.1.2 ping statistics ---                            
        5 packet(s) transmitted                                   
        5 packet(s) received                                      
        0.00% packet loss                                         
        round-trip min/avg/max = 1/1/1 ms                         
                                                                  
    ```



4. 配置静态路由

    \# 配置RouterA。

    ```
    [RouterA] ip route-static 10.2.1.0 255.255.255.0 tunnel 0/0/1
    ```

    \# 配置RouterC。

    ```
    [RouterC] ip route-static 10.1.1.0 255.255.255.0 tunnel 0/0/1
    ```

    \# 配置完成后，在RouterA和RouterC上执行**display ip routing-table**命令，可以看到去往对端用户侧网段的静态路由出接口为Tunnel接口。

    \# 以RouterA的显示为例。

    ```
    [RouterA] display ip routing-table 10.2.1.0
    <keyword conref="../commonterms/commonterms.xml#commonterms/route-flags"></keyword>                                   
    ------------------------------------------------------------------------------
    Routing Table : Public                                                        
    Summary Count : 1                                                             
    Destination/Mask    Proto   Pre  Cost      Flags NextHop         Interface    
                                                                                  
           10.2.1.0/24  Static  60   0           D   10.3.1.2        Tunnel0/0/1  
                                                                          
    ```

    PC1和PC2可以相互Ping通。

    

    \# 配置 OSPF 动态路由协议。

    \# 配置RouterA。

    ```
    #
    ip ip-prefix direct index 10 permit 192.168.1.0 24
    #
    
    #
    route-policy direct permit node 10
     if-match ip-prefix direct
    #
    
    #
    ospf 2
     import-route direct route-policy direct
     area 0.0.0.0
      network 192.168.13.0 0.0.0.255
    #
    ```

    \# 配置RouterC。

    ```
    #
    ip ip-prefix direct index 10 permit 10.1.1.0 24
    #
    
    #
    route-policy direct permit node 10
     if-match ip-prefix direct
    #
    
    #
    ospf 2
     import-route direct route-policy direct
     area 0.0.0.0
      network 192.168.13.0 0.0.0.255
    #
    ```

    \# 路由信息通过 OSPF 协议学习到。

    ```
    Route Flags: R - relay, D - download to fib
    ------------------------------------------------------------------------------
    Routing Tables: Public
             Destinations : 10       Routes : 10       
    
    Destination/Mask    Proto   Pre  Cost      Flags NextHop         Interface
    
           10.1.1.0/24  O_ASE   150  1           D   192.168.13.3    Tunnel0/0/1
    ```

    

​	
