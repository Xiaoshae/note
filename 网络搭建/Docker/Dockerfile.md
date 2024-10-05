# Dockerfile

Docker 通过读取 Dockerfile 中的指令来构建镜像。

Dockerfile 的默认文件名是 `Dockerfile` ，没有文件扩展名。使用默认名称可以使您在运行 `docker build` 命令时无需指定其他命令标志。

Docker 镜像由多个层组成。每一层都是 Dockerfile 中构建指令的结果。这些层按顺序堆叠，每一层代表对前一层应用的更改增量。

Dockerfile 中的注释以 `#` 符号开始。



## syntax

在 Dockerfile 中添加的第一行是一个 `# syntax` 解析器指令。

虽然此指令是可选的，但它会指示 Docker 构建器在解析 Dockerfile 时使用什么语法，并允许启用了 BuildKit 的旧版 Docker 使用特定的 Dockerfile 前端在开始构建之前。

解析器指令必须出现在 Dockerfile 中任何其他注释、空白或指令之前，并且应该是 Dockerfile 中的第一行。

```dockerfile
# syntax=docker/dockerfile:1
```



注意：建议使用 docker/dockerfile:1 ，它始终指向版本 1 语法的最新发布。BuildKit 会在构建之前自动检查语法更新，确保您使用的是最新版本。



## FROM 镜像

语法指令后面的行定义了要使用的基础镜像：

```dockerfile
FROM ubuntu:22.04
```



## RUN 执行命令

以下行在基础镜像内执行一个命令。

```dockerfile
RUN apt-get update && apt-get install -y python3 python3-pip
```



## COPY 复制文件

使用 `COPY` 指令将 `hello.py` 文件从本地构建上下文复制到我们镜像的根目录。

```dockerfile
COPY hello.py /
```



## ENV 环境变量

如果您的应用程序使用环境变量，您可以使用 `ENV` 指令在 Docker 构建中设置环境变量。

```dockerfile
ENV FLASK_APP=hello
```



## Exposed 暴露端口

`EXPOSE` 指令标记我们的最终镜像在端口 `8000` 上有一个正在监听的服务。

```Dockerfile
EXPOSE 8000
```

此指令不是必需的，但这是一个好的实践，并有助于工具和团队成员了解此应用程序正在执行的操作。



## CMD 启动应用程序

`CMD` 指令设置了当用户基于此镜像启动容器时运行的命令。

此命令启动在所有地址上的 8000 端口监听的 flask 开发服务器。

```dockerfile
CMD ["flask", "run", "--host", "0.0.0.0", "--port", "8000"]
```



这里的示例使用了 “exec 形式” 版本的 CMD 。也可以使用 “shell 形式”：

```dockerfile
CMD flask run --host 0.0.0.0 --port 8000
```



注意：这两个版本之间有一些细微差别，例如它们如何捕获像 `SIGTERM` 和 `SIGKILL` 这样的信号。详细差别这里不介绍。





## build 构建

Dockerfile 构建容器镜像，使用 `docker build` 命令：

`-t test:latest` 选项指定了镜像的名称和标签。

命令末尾的单个点 ( `.` ) 将构建上下文设置为当前目录。

这意味着构建期望在调用命令的目录中找到 Dockerfile 和 `hello.py` 文件。如果这些文件不存在，构建将失败。

```
docker build -t test:latest .
```













