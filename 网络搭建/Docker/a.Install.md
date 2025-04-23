# Install Docker

> Docker CE是免费的Docker产品的新名称，Docker CE包含了完整的Docker平台，非常适合开发人员和运维团队构建容器APP。



## Centos 7 / 8 / 9 online

```bash
#!/bin/bash

# step 1: 安装必要的一些系统工具
sudo yum install -y yum-utils device-mapper-persistent-data lvm2

# Step 2: 添加软件源信息
sudo yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo

# Step 3: 添加 Docker yum 源
sudo sed -i 's+download.docker.com+mirrors.aliyun.com/docker-ce+' /etc/yum.repos.d/docker-ce.repo

# Step 4: 更新缓存
sudo yum makecache

# Step 5: 安装Docker-CE
sudo yum -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 启动 Docker 添加到开机自启
systemctl enable docker --now
```



## ubuntu 24.04

```bash
#!/bin/bash

# step 1: 更新系统到最新
sudo apt-get update
sudo apt update
sudo apt -y upgrade 

# step 2: 安装必要的一些系统工具
sudo apt -y install apt-transport-https ca-certificates curl software-properties-common

# step 3: 添加 Docker 密钥
curl -fsSL http://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# step 4: 添加 Docker 源
# 选项 1: 清华大学源
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/ubuntu "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# 选项 2: 阿里云源
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://mirrors.aliyun.com/docker-ce/linux/ubuntu "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  
# 选项 3: 阿里云源(ECS服务器)
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] http://mirrors.cloud.aliyuncs.com/docker-ce/linux/ubuntu "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# step 5: 更新 apt 缓存并安装 Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# step 6: 启动 Docker
sudo systemctl enable docker

sudo systemctl start docker
```



# 其他说明

参考链接：

1. [安装 Docker-CE 阿里巴巴镜像站](https://developer.aliyun.com/mirror/docker-ce)
1. [安装 Docker-CE 清华大学开源软件镜像站](https://mirrors.tuna.tsinghua.edu.cn/help/docker-ce/)



编写信息：

Name：XiaoshaeCrocodile

Email：xiaoshae@gmail.com

Github：[xiaoshae](https://github.com/xiaoshae)



**特别说明：文章内容并非完全原创，参考许多文章进行整合。**