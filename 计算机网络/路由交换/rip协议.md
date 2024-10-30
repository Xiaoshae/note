# RIP

## 原理描述

RIP是Routing Information Protocol（路由信息协议）的简称，它是一种较为简单的内部网关协议（Interior Gateway Protocol）。

RIP是一种基于距离矢量（Distance-Vector）算法的协议，它使用跳数（Hop Count）作为度量来衡量到达目的网络的距离。

RIP通过UDP报文进行路由信息的交换，使用的端口号为520。

RIP包括RIP-1和RIP-2两个版本，RIP-2对RIP-1进行了扩充，使其更具有优势。



RIP多进程允许为指定的RIP进程关联一组接口，从而保证该进程进行的所有协议操作都仅限于这一组接口。这样，就可以实现一台设备有多个RIP进程，不同RIP进程之间互不影响，它们之间的路由交互相当于不同路由协议之间的路由交互。



### RIP路由表形成过程

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download.png)

RIP路由形成的过程如图4-1所示。

1. RIP协议启动之后，SwitchA会向相邻的交换机广播一个Request报文。
2. SwitchB从接口接收到SwitchA发送的Request报文后，把自己的RIP路由表封装在Response报文内，然后向该接口对应的网络广播。
3. SwitchA根据SwitchB发送的Response报文，形成自己的路由表。



### RIP度量

在RIP网络中，缺省情况下，设备到与它直接相连网络的跳数为0，经过一个设备可达的网络的跳数为1，其余依此类推。

度量值等于从本网络到达目的网络间的设备数量。



如图4-3所示，S1去往192.168.10.0/24网段的路径有两条：

- S1-S2-S5，中间经过S2、S5两台设备，该路径的度量值为2跳，带宽为1.544Mbit/s
- S1-S3-S4-S5，中间经过S3、S4、S5三台设备，该路径的度量值为3跳，但是带宽很大，为千兆链路

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download-1730256760469-3.png)

按照RIP的度量标准，转发报文时会优选经过S2的这条路径，但这条路径的链路带宽并不是最优的。

此外，为了防止RIP路由在网络中被无限泛洪使得跳数累加到无穷大，同时也为了限制收敛时间，RIP规定度量值取0～15之间的整数，大于或等于16的跳数被定义为无穷大，即目的网络或主机不可达。



### RIP的更新与维护

RIP协议在更新和维护路由信息时主要使用**三个定时器**：

- 更新定时器（Update timer）：当此定时器超时时，立即发送更新报文。
- 老化定时器（Age timer）：RIP设备如果在老化时间内没有收到邻居发来的路由更新报文，则认为该路由不可达。
- 垃圾收集定时器（Garbage-collect timer）：如果在垃圾收集定时器倒计时结束前，不可达路由没有收到来自同一邻居的更新报文，则该路由将从RIP路由表中彻底被删除。

**RIP路由与定时器之间的关系**：

- RIP的更新信息发布是由更新定时器控制的，默认为每30秒发送一次。
- 每一条路由表项对应两个定时器：老化定时器和垃圾收集定时器。当学到一条路由并添加到RIP路由表中时，老化定时器启动。如果老化定时器超时，设备仍没有收到邻居发来的更新报文，则把该路由的度量值置为16（表示路由不可达），并启动垃圾收集定时器。如果垃圾收集定时器超时，设备仍然没有收到更新报文，则在RIP路由表中删除该路由。



### 触发更新

触发更新是指当路由信息发生变化时，立即向邻居设备发送触发更新报文，而不用等待更新定时器超时，从而避免产生路由环路。

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download-1730256897488-6.png)

如图4-4所示，网络10.4.0.0不可达时，SwitchC最先得到这一信息。

- 如果设备不具有触发更新功能，SwitchC发现网络故障之后，需要等待更新定时器超时。在等待过程中，如果SwitchB的更新报文传到了SwitchC，SwitchC就会学到SwitchB的去往网络10.4.0.0的错误路由。这样SwitchB和SwitchC上去往网络10.4.0.0的路由都指向对方从而形成路由环路。
- 如果设备具有触发更新功能，SwitchC发现网络故障之后，不必等待更新定时器超时，立即发送路由更新信息给交换机B，这样就避免了路由环路的产生。



## 水平分割和毒性反转

### 水平分割

水平分割（Split Horizon）的原理是，RIP从某个接口学到的路由，不会从该接口再发回给邻居路由器。这样不但减少了带宽消耗，还可以防止路由环路。

水平分割在不同网络中实现有所区别，分为按照接口和按照邻居进行水平分割。广播网、P2P和P2MP网络中是按照接口进行水平分割的。



#### 接口

按照接口进行水平分割原理图

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download-1730257049191-9.png)

RouterA会向RouterB发送到网络10.0.0.0/8的路由信息，如果**没有配置水平分割**，RouterB会将从RouterA学习到的这条路由再发送回给RouterA。

RouterA可以学习到两条到达10.0.0.0/8网络的路由：跳数为0的直连路由；下一跳指向RouterB，且跳数为2的路由。



在RouterA的RIP路由表中只有直连路由才是活跃的，当RouterA到网络10.0.0.0的路由变成不可达，并且RouterB还没有收到路由不可达的信息时，RouterB会继续向RouterA发送10.0.0.0/8可达的路由信息。

即，RouterA会接收到错误的路由信息，认为可以通过RouterB到达10.0.0.0/8网络；而RouterB仍旧认为可以通过RouterA到达10.0.0.0/8网络，从而形成路由环路。



#### 邻居

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download-1730257178030-12.png)

在NBMA网络配置了水平分割之后，RouterA会将从RouterB学习到的172.16.0.0/16路由发送给RouterC，但是不会再发送回给RouterB。



### 毒性反转

毒性反转（Poison Reverse）的原理是，RIP从某个接口学到路由后，从原接口发回邻居路由器，并将该路由的开销设置为16（即指明该路由不可达）。利用这种方式，可以清除对方路由表中的无用路由。

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download-1730257215357-15.png)

配置毒性反转后，RouterB在接收到从RouterA发来的路由后，向RouterA发送一个这条路由不可达的消息（将该路由的开销设置为16），这样RouterA就不会再从RouterB学到这条可达路由，因此就可以避免路由环路的产生。



#### 示例

![image-20241030110201015](./images/rip%E5%8D%8F%E8%AE%AE.assets/image-20241030110201015.png)

![image-20241030110253058](./images/rip%E5%8D%8F%E8%AE%AE.assets/image-20241030110253058.png)

![image-20241030110325144](./images/rip%E5%8D%8F%E8%AE%AE.assets/image-20241030110325144.png)

![image-20241030110355940](./images/rip%E5%8D%8F%E8%AE%AE.assets/image-20241030110355940.png)

![image-20241030110421357](./images/rip%E5%8D%8F%E8%AE%AE.assets/image-20241030110421357.png)



## RIP-2的增强特性

RIP-1 报文格式

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download-1730258334783-21.png)

RIP-2 报文格式

![img](./images/rip%E5%8D%8F%E8%AE%AE.assets/download-1730258343067-24.png)

RIP-1（即RIP version1）是有类别路由协议（Classful Routing Protocol），它只支持以广播方式发布协议报文，协议报文中没有携带掩码信息，它只能识别A、B、C类这样的自然网段的路由，因此RIP-1无法支持路由聚合，也不支持不连续子网（Discontiguous Subnet）。

RIP-2（即RIP version2）是一种无分类路由协议（Classless Routing Protocol）。

与RIP-1相比，RIP-2具有以下优势：

- 支持外部路由标记（Route Tag），可以在路由策略中根据Tag对路由进行灵活的控制。
- 报文中携带掩码信息，支持路由聚合和CIDR（Classless Inter-Domain Routing）。
- 支持指定下一跳，在广播网上可以选择到目的网段最优下一跳地址。
- 支持以组播方式发送更新报文，只有支持RIP-2的设备才能接收协议报文，减少资源消耗。
- 支持对协议报文进行验证，增强安全性。



### RIP-2路由聚合

路由聚合的原理是，同一个自然网段内的不同子网的路由在向外（其它网段）发送时聚合成一个网段的路由发送。

在RIP-2中进行路由聚合可提高大型网络的可扩展性和效率，缩减路由表。

路由聚合有两种方式：

- 基于RIP进程的有类聚合：

  聚合后的路由使用自然掩码的路由形式发布。比如，对于10.1.1.0/24（metric=2）和10.1.2.0/24（metric=3）这两条路由，会聚合成自然网段路由10.0.0.0/8（metric=2）。RIP–2聚合是按类聚合的，聚合得到最优的metric值。

- 基于接口的聚合：

  用户可以指定聚合地址。比如，对于10.1.1.0/24（metric=2）和10.1.2.0/24（metric=3）这两条路由，可以在指定接口上配置聚合路由10.1.0.0/16（metric=2）来代替原始路由。



## 命令参考

执行命令 **system-view**，进入系统视图。



启动RIP进程

```
rip [ process-id ] 
```



为RIP进程配置描述信息（可选）

```
description text
```



禁止对RIP报文的源地址检查（可选）

```
undo verify-source
```

当P2P网络中链路两端的IP地址属于不同网络时，只有取消报文的源地址进行检查，链路两端才能建立起正常的邻居关系。



指定网段使能RIP

```
network network-address
```

注意：

- *network-address* 为自然网段的地址。
- 一个接口只能与一个RIP进程相关联。



配置RIP邻居

```
peer ip-address
```

通常情况下，RIP使用广播或组播地址发送报文。

如果在不支持广播或组播报文的链路上运行RIP，则必须在链路两端手工相互指定RIP的邻居，这样报文就会以单播形式发送到对端。



配置全局RIP版本号（进入RIP视图）

```
version { 1 | 2 }
```

缺省情况下，接口只发送RIP-1报文，但可以接收RIP-1和RIP-2的报文。



配置接口的RIP版本号（进入接口视图）

```
rip version { 1 | 2 [ broadcast | multicast ] }
```

- 缺省情况下，接口只发送RIP-1报文，但可以接收RIP-1和RIP-2的报文。
- 如果没有配置接口的RIP版本号则以全局版本为准，接口下配置的版本号优先级高于全局版本号。



配置水平分割（进入接口视图）

```
rip split-horizon
```



配置毒性反转（进入接口视图）

```
rip poison-reverse
```



自动路由聚合（RIP视图）

```
summary always
```

- RIP Version 必须为 RIP-2
- 不论水平分割和毒性反转是否使能，都可以使能RIP-2自动路由聚合



配置RIP-2手动路由聚合（接口视图）

```
rip summary-address ip-address mask [ avoid-feedback ]
```

配置RIP-2发布聚合的本地IP地址。

- **ip-address**: 指定汇总路由的目的网络地址。这是一个IPv4地址，代表了要汇总的一系列子网的起始地址。
- **mask**: 子网掩码，用于确定汇总路由所覆盖的地址范围。
- **avoid-feedback** (可选): 当配置了此选项时，路由器将不会向其邻居发送汇总路由中包含的具体子网路由，避免了可能引起的路由环路。



检查RIP基本功能配置结果

- 使用**display rip** [ *process-id* | **vpn-instance** *vpn-instance-name* ]命令查看RIP的当前运行状态及配置信息。
- 使用**display rip** *process-id* **route**命令查看所有从其他设备学习到的RIP路由。
- 使用**display default-parameter rip**命令查看RIP的缺省配置信息。
- 使用**display rip** *process-id* **statistics** **interface** { **all** | *interface-type interface-number* [ **verbose** | **neighbor** *neighbor-ip-address* ] }命令查看RIP接口的统计信息。



