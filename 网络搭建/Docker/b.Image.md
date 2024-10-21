# Docker 镜像管理



## 第三方镜像

> 因为 docker 官方镜像服务器在国外，下载速度慢，可能连接不上，所以需要配置国内镜像下载地址。

```
mkdir -p /etc/docker
vim /etc/docker/daemon.json
{
  "registry-mirrors": ["https://xxx.com"]
}

#实际上可以省略这一步，但是官方文档上有这一步骤，所以最好是不省略
#只有修改了docker服务的启动脚本，才需要执行该命令
systemctl daemon-reload

#重启docker服务，完成配置
systemctl restart docker
```

注意：即使配置国内镜像服务器，默认也会保留国外的，首先访问的是国内源，如果无法访问国内的，就会自动去访问国外的源



## Search

`docker search` 在配置的镜像服务器中搜索镜像

```
作用：docker search [选项(可选)] [镜像名称:标签]
选项：
   -f, --filter filter 根据提供的条件过滤输出
       --format string 使用 Go 模板进行漂亮打印搜索
       --limit int 最大搜索结果数（默认 25）
       --no-trunc 不截断输出
```



示例：搜索 openjdk 的镜像，仅显示一个结果

```
[root@localhost /]# docker search --limit 1 openjdk
NAME      DESCRIPTION                                     STARS     OFFICIAL
openjdk   Pre-release / non-production builds of OpenJ…   3954      [OK]


参数说明：
NAME：镜像仓库源的名称
DESCRIPTION：镜像的描述
OFFICIAL：是否 docker 官方发布
stars：类似 Github 里面的 star，表示点赞、喜欢的意思。
Automated：自动构建。
```



## Images

`docker images` 查看镜像

```
作用：docker images [选项](可选) [镜像名[:标签]](可选)
选项：
   -a, --all 显示所有图像（默认隐藏中间图像）
       --digests 显示摘要
   -f, --filter filter 根据提供的条件过滤输出
       --format string 使用 Go 模板漂亮地打印图像
       --no-trunc 不截断输出
   -q, --quiet 只显示图像 ID
```



### 示例一：查看所有docker镜像

```
[root@localhost /]# docker images -a 
REPOSITORY           TAG                   IMAGE ID       CREATED         SIZE
openjdk              24-jdk-oraclelinux9   3c6db179c055   5 days ago      576MB
nginx                1.27.1                39286ab8a5e1   4 weeks ago     188MB
openjdk              21-jdk-oraclelinux8   079114de2be1   11 months ago   504MB
openjdk              21-jdk-slim           a48f4cb73730   11 months ago   439MB
openjdk              21-slim               a48f4cb73730   11 months ago   439MB
```



### 示例二：查看镜像名为 openjdk 的docker镜像

```
[root@localhost /]# docker images openjdk
REPOSITORY   TAG                   IMAGE ID       CREATED         SIZE
openjdk      24-jdk-oraclelinux9   3c6db179c055   5 days ago      576MB
openjdk      21-jdk-oraclelinux8   079114de2be1   11 months ago   504MB
openjdk      21-jdk-slim           a48f4cb73730   11 months ago   439MB
openjdk      21-slim               a48f4cb73730   11 months ago   439MB
```



### 示例三：查看镜像名为 openjdk 标签为 21-jdk-slim 的 docker 镜像

```
[root@localhost /]# docker images openjdk:21-jdk-slim
REPOSITORY   TAG           IMAGE ID       CREATED         SIZE
openjdk      21-jdk-slim   a48f4cb73730   11 months ago   439MB
```



## pull

`docker pull` 从registry中拉取映像或存储库。

```
作用：docker pull [选项] 名称[:标签|@DIGEST]
选项：
   -a, --all-tags 下载存储库中的所有标记图像
       --disable-content-trust 跳过图像验证（默认为 true）
       --platform string 如果服务器支持多平台，则设置平台
   -q, --quiet 抑制详细输出
```



**示例：拉去 openjdk:23-jdk-slim 镜像**

```
[root@hongkong /]# docker pull openjdk:23-jdk-slim
23-jdk-slim: Pulling from library/openjdk
a2318d6c47ec: Already exists 
249d8fef5e46: Pull complete 
c21c214f0b68: Pull complete 
Digest: sha256:7e7ee1ee0e0e4819beb1a4b04b4035f34df405410691459e05c10a859661dc35
Status: Downloaded newer image for openjdk:23-jdk-slim
docker.io/library/openjdk:23-jdk-slim
```



## load

`docker load` 导入本地镜像

```
作用：docker load [选项] [文件路径]
选项：
   -i, --input string 从 tar 存档文件中读取，而不是 STDIN
   -q, --quiet 抑制负载输出 
```



示例：导入tar文件到镜像中

```
[root@localhost docker-images]# ls     #将文件导入到Linux系统中
busybox.tar

[root@localhost docker-images]# docker load -i busybox.tar   #导入到docker镜像中
Loaded image: busybox:latest

[root@localhost docker-images]# docker images busybox   #查看是否导入成功
REPOSITORY   TAG       IMAGE ID       CREATED      SIZE
busybox      latest    d23834f29b38   8 days ago   1.24MB
```



## tag

`docker tag` 将指定的镜像重新打上标签



示例：给 centos:latest 重新打上标签为 centos:8.4.2105 。

```
#查看现有的centos的docker镜像
[root@localhost /]# docker images centos  
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
centos       latest    5d0da3dc9764   2 months ago   231MB

#将其重新打上标签
[root@localhost /]# docker tag centos:latest centos:8.4.2105   

#再次查看现有的centos的docker镜像，发现多了一个
[root@localhost /]# docker images centos   
REPOSITORY   TAG        IMAGE ID       CREATED        SIZE
centos       8.4.2105   5d0da3dc9764   2 months ago   231MB
centos       latest     5d0da3dc9764   2 months ago   231MB

#镜像名也是可以修改的
[root@localhost /]# docker tag centos:latest linux-centos:8.4.2105  

#查看linux-centos的docker标签
[root@localhost /]# docker images linux-centos   
REPOSITORY     TAG        IMAGE ID       CREATED        SIZE
linux-centos   8.4.2105   5d0da3dc9764   2 months ago   231MB
```





## rmi

`docker rmi` 删除镜像

```
语法：docker rmi [选项] [镜像名:标签]
作用：删除指定的docker镜像
选项：
   -f, --force 强制删除镜像
       --no-prune 不要删除未标记的镜像
```



示例：删除 openjdk:23-jdk-slim 镜像

```
[root@hongkong /]# docker rmi openjdk:23-jdk-slim
Untagged: openjdk:23-jdk-slim
Untagged: openjdk@sha256:7e7ee1ee0e0e4819beb1a4b04b4035f34df405410691459e05c10a859661dc35
Deleted: sha256:e419d13420ebe46cf290e7b098b4e784de3d7d4970d134b8c06c5690ccfa4e7b
Deleted: sha256:cdf3e18de5693bcc6d9b63dea5b0c3a94e1265143f24aa9acadaaba1ee2ae5f3
Deleted: sha256:b3533383858e60cbd082fa6a6ec90eef9da699a41889b69c1bd6017d1ea4ec07
```

