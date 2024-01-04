# 记录一个可能是微软DNS服务器BUG

两台主机（同一网段，防火墙已关闭）：

- 主机A安装Windows Server 2019 数据中心版本

- 主机B安装Windows 10专业版



主机A中主机名修改为windows1，然后安装域控制器，新增一个林为skills.com。在安装域控制器后，会自动安装DNS。此时DNS服务器已经自动创建好，DNS服务器中由正向查找区（skills.com）

有两条解析

- @.skills.com(skills.com)
- windows1.skills.com

![image-20231204203928293](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204203928293.png)



主机B，使用nslookup解析skills.com，指定使用DNS服务器地址为主机B的IP地址。

注：这样无需设置主句B的网卡的DNS服务器地址，如果设置了DNS服务器地址，有一些Windows默认服务会进行DNS解析影响抓包分析。



skills.com成功解析，但是nslookup报错说请求超时，超时时间2秒，明明解析成功了为什么还会显示DNS超时呢？

![image-20231204204326284](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204204326284.png)



## WireShark抓包分析

![image-20231204204618817](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204204618817.png)

- 第一个数据包为DNS反向解析的请求，请求DNS服务器IP所对应的域名。可以得出Windows中使用nslookup默认会发送一条DNS反向解析请求，请求DNS服务器IP地址所对应的域名。（注：CentOS8.5或Linux下的nslookup工具默认不会发送DNS反向解析请求DNS服务器IP地址所对应的域名，已经WireShark远程抓包确认）
- （过了两秒后）第二个数据包为skills.com域名解析的正向请求，（过了0.000759秒）后DNS服务器返回了skills.com域名对应的IP地址。
- （过了7秒后）DNS服务器返回了一个数据包，告知客户端（nslookup工具）请求DNS服务器IP的反向解析失败。



使用nslookup会送一条DNS反向解析请求，请求DNS服务器IP地址所对应的域名，两秒钟内DNS服务器没有任何回复，到达nslookup工具默认的超时时间，输出"DNS request time out......"，然后发送DNS请求解析skills.com，DNS服务器查询到对应的IP地址后，立马返回了数据，成功解析skills.com。（过了7秒后），DNS服务器返回了，反向解析失败的数据包，但是此时已经过了nslookup的超时时间，nslookup工具并不会理会该数据包。



进行多次解析发现其超时时间每次都不一致

![image-20231204213450698](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204213450698.png)

![image-20231204213523558](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204213523558.png)

## 设置DNS转发器

DNS服务器没有查询到反向解析后应该立法返回解析失败的数据包，为什么会等待这么久才返回解析失败呢？在DNS中有转发器，DNS服务器接收到一个请求后，在本DNS服务器上没有查询到该请求对应的解析，就会通过DNS转发器，将DNS请求转发到另一个DNS服务器上进行查询。



在这里将根提示给禁用掉，此处无需知晓根提示是如何造成的。

![image-20231204213236130](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204213236130.png)





在安装好域后并没有设置DNS转发器，查看DNS转发器的设置，发现其中默认有三条转发器（此处不用理会），转发器默认超时时间为3秒。

![image-20231204210836368](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204210836368.png)



删除两条转发器后再次进行测试。发现解析失败的时间基本上为3秒钟左右。

![image-20231204214248664](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204214248664.png)

![image-20231204214226230](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204214226230.png)

![image-20231204214139193](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204214139193.png)



修改解析器超时时间为1秒钟。发现反向解析失败返回时间约为1秒，且nslookup没有出现DNS超时了

![image-20231204214357070](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204214357070.png)

![image-20231204214426392](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204214426392.png)

![image-20231204214520899](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204214520899.png)



勾选"如果没有可用转发器，则使用根提示器"，然后在根提示器中删掉所有内容，进行测试

![image-20231204215133920](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204215133920.png)



反向解析失败立马返回，且nslookup没有出现DNS超时了

![image-20231204215244441](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204215244441.png)







## 禁用DNS转发器

将其他的DNS设置恢复为默认，然后禁用DNS递归查询（也禁用转发器）

![image-20231204211034528](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204211034528.png)



再次尝试DNS解析，没有显示DNS超时了

查看WireShark抓取的数据包，发送DNS反向解析后，DNS服务器里面就返回了解析失败的请求。

![image-20231204211116534](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204211116534.png)

![image-20231204211204267](images/%E8%BD%AC%E5%8F%91%E5%99%A8BUG.assets/image-20231204211204267.png)



按照正常的逻辑，删除所有转发器设置的DNS服务器IP地址，取消勾选"如果没有可用转发器，则使用根提示器"，如果本地DNS没有查询到，则会立马返回解析失败的数据包，而不需要等待这么多秒。



## 可能存在的其他BUG

注：该DNS设置中可能出现其他BUG

例1：删除所有转发器IP地址后，无法编辑取消勾选"如果没有可用转发器，则使用根提示器"。

例2：如果先取消勾选"如果没有可用转发器，则使用根提示器"，再删除所有转发器的DNS服务器IP地址后，显示已经取消勾选，但实际上为没有取消勾选。

例3：如果先取消勾选"如果没有可用转发器，则使用根提示器"，再删除所有转发器的DNS服务器IP地址后，点击保存，"如果没有可用转发器，则使用根提示器"又变成勾选状态。

例4：删除所有转发器IP地址后，可以编辑超时时间，但是保存后又会恢复的默认三秒钟。

例5：有时删除所有转发器IP地址后，编辑超时时间保存后，显示出来的时间没有恢复默认的3秒钟，但实际效果和默认的3秒钟相同。