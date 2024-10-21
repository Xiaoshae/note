# 	Docker Compose

使用Docker Compose，您可以使用YAML配置文件（称为Compose文件）来配置应用程序的服务，然后使用Compose CLI从配置中创建并启动所有服务。

Compose文件的默认路径是 compose.yaml（首选）或 compose.yml，位于工作目录中。Compose还支持docker-compose.yaml和docker-compose.yml，以向后兼容早期版本。如果这两个文件都存在，则**Compose首选规范的compose.yaml**。



## Compose CLI

Docker CLI允许您通过 **docker compose** 命令及其子命令与Docker Compose应用程序交互。使用CLI，您可以管理`compose.yaml`文件中定义的多容器应用程序的生命周期。



### 关键命令

启动 **compose.yaml** 文件中定义的所有服务：

```
docker compose up
```



要停止并删除正在运行的服务，请执行以下操作：

```
docker compose down 
```



如果您想监视正在运行的容器的输出和调试问题，可以使用以下命令查看日志：

```
docker compose logs
```



列出所有服务沿着当前状态：

```
docker compose ps
```



## compose.yaml



### version(已废弃)

**version** 属性最初是为了确保 Compose 文件在不同版本的 Compose 工具之间能够兼容而引入的。

在最新的 Compose 规范中，version 属性已经**不再用于选择具体的文件格式版本**。

如果你在 Compose 文件中指定了 version 属性，Compose 工具会**显示一条警告消息，提示该属性已经过时**。



### name

name 用于设置 Docker Compose 中项目的名称。

**默认值**：所在目录的名字自动选择一个作为默认的项目名称。

**环境变量**：Compose 文件或其他配置文件中使用 `${COMPOSE_PROJECT_NAME}` 来引用这个变量，从而实现动态配置。

```yaml
version: "3"
name: myapp

services:
  foo:
    image: busybox
    command: echo "I'm running ${COMPOSE_PROJECT_NAME}"
```



### server

Compose 文件必须声明一个 services 顶层元素，应用于每个服务**容器的配置**。

每个 services 还可以包括一个**可选的 build 部分**，该部分定义如何创建 Docker 镜像。



以下示例演示了如何使用 Docker Compose 定义两个简单服务、设置它们的镜像、映射端口和配置基本环境变量。

```yaml
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"

  db:
    image: postgres:13
    environment:
      POSTGRES_USER: example
      POSTGRES_DB: exampledb
```



#### container_name 容器名称

container_name 是一个指定自定义容器名称的字符串，而不是默认生成的名称。

```yaml
container_name: nginx
```



#### image 镜像

image 指定了启动容器的镜像，如果平台不存在该镜像，Compose 会尝试根据 `pull_policy` 拉取它。

```yaml
images: nginx:latest
```



#### pull_policy 拉取策略

`pull_policy` 定义了 Compose 在开始拉取镜像时所做的决定。可能的值是：

- `always` : Compose 始终从仓库拉取镜像。
- `never` : Compose 不从仓库拉取镜像，而是依赖平台的缓存镜像。如果没有缓存镜像，则报告失败。
- `missing` ：如果平台缓存中没有该镜像，Compose 仅会拉取该镜像。如果你未使用 Compose 构建规范，这是默认选项。 `if_not_present` 被认为是此值的别名，以保持向后兼容性。
- `build` : Compose 构建镜像。如果镜像已存在，Compose 会重新构建镜像。



#### build 构建

Build 是 Compose 规范的可选部分。它告诉 Compose 如何从源 (重新) 构建应用程序，并允许您以可移植的方式在 Compose 文件中定义构建过程。

`build` 可以定义为单个字符串，指定上下文路径以执行 Docker 构建，在目录的根目录中查找规范的 `Dockerfile` 。

路径可以是绝对的或相对的。如果是相对路径，则从包含您的 Compose 文件的目录中解析。如果是绝对路径，则该路径会阻止 Compose 文件具有可移植性，因此 Compose 会显示警告。



当 Compose 遇到服务的 **build 子节和 image 属性**时，它遵循由 **pull_policy** 属性定义的规则。



以下示例通过一个具体的样本应用程序来说明 Compose 构建规范的概念。该样本是非规范性的。

```yaml
services:
  frontend:
    image: example/webapp
    build: ./webapp

  backend:
    image: example/database
    build:
      context: backend
      dockerfile: ../backend.Dockerfile

  custom:
    build: ~/custom
```

当从源代码构建服务镜像时，Compose 文件会创建三个 Docker 镜像：

- `example/webapp` : 使用位于 Compose 文件父文件夹内的 `webapp` 子目录作为 Docker 构建上下文来构建 Docker 镜像。如果此文件夹内没有 `Dockerfile` ，则会引发错误。
- `example/database` : 使用位于 Compose 文件父文件夹内的 `backend` 子目录来构建 Docker 镜像。使用 `backend.Dockerfile` 文件定义构建步骤，此文件相对于上下文路径进行搜索，这意味着 `..` 解析为 Compose 文件的父文件夹，因此 `backend.Dockerfile` 是一个同级文件。
- 使用 `custom` 目录构建 Docker 镜像，用户的 HOME 作为 Docker 构建上下文。Compose 显示关于用于构建镜像的非便携路径的警告。



在推送时， `example/webapp` 和 `example/database` Docker 镜像都会推送到默认注册表。由于未设置 `image` 属性， `custom` 服务镜像被跳过，Compose 显示关于此缺失属性的警告。



##### context 上下文

`context` 定义了包含 Dockerfile 的目录路径，或者指向 git 仓库的 URL。

```yml
build:
  context: ./dir
```

```yml
services:
  webapp:
    build: https://github.com/mycompany/webapp.git
```



##### cache_from 从缓存

`cache_from` 定义了图像构建器应用于缓存解析的源列表。

```yml
build:
  context: .
  cache_from:
    - alpine:latest
    - type=local,src=path/to/cache
    - type=gha
```

- alpine:latest 这条指令告诉 Docker 使用 `alpine:latest` 镜像作为缓存来源
- type=local,src=path/to/cache
  - `type=local` 表示缓存类型是本地文件系统。
  - `src=path/to/cache` 指定了本地缓存的路径。
- type=gha 表示缓存类型是 GitHub Actions 缓存。



##### cache_to 缓存到

`cache_to` 定义了一个导出位置列表，用于与将来构建共享构建缓存。

```yml
build:
  context: .
  cache_to:
   - user/app:cache
   - type=local,dest=path/to/cache
```



##### dockerfile

dockerfile 设置了一个备用的 Dockerfile。

```
build:
  context: .
  dockerfile: webapp.Dockerfile
```

设置后， `dockerfile_inline` 属性将不允许。



##### dockerfile_inline

`dockerfile_inline` 在 Compose 文件中将 Dockerfile 内容定义为内联字符串。

建议使用 YAML 多行字符串语法来定义 Dockerfile 内容：

```yml
build:
  context: .
  dockerfile_inline: |
    FROM baseimage
    RUN some command   
```



##### no_cache 不缓存

no_cache 禁用图像构建缓存，并强制从源完全重新构建所有图像层。



##### pull 拉取

`pull` 需要图像构建器拉取引用的图像（ `FROM` Dockerfile 指令），即使这些图像已经存在于本地图像存储中。



##### tags 标签

`tags` 定义了必须与构建映像关联的标签映射列表。此列表补充了服务部分中定义的 `image` 属性

```yml
tags:
  - "myimage:mytag"
  - "registry/username/myrepos:my-other-tag"
```



#### ports 端口映射

`ports` 用于定义主机和容器之间的端口映射。这对于允许外部访问容器内运行的服务至关重要。

可以使用简短语法进行简单的端口映射，或使用包含额外选项（如协议类型和网络模式）的长语法。

注意：端口映射不得与 `network_mode: host` 一起使用，否则会发生运行时错误。

```yaml
ports:
  - 80:80
    443:443/udp
  	0.0.0.0:8080:8080/tcp
  	[::]:8443:8443/udp
```



#### command 默认命令

`command` 覆盖由容器镜像（例如 Dockerfile 的 `CMD` ）声明的默认命令。

```yaml
command: bundle exec thin -p 3000
```



值也可以是一个列表，类似于 Dockerfile 的方式：

```yaml
command: [ "bundle", "exec", "thin", "-p", "3000" ]
```



如果值是 `null` ，则使用来自镜像的默认命令。

如果值为 `[]` （空列表）或 `''` （空字符串），则忽略由镜像声明的默认命令，即覆盖为空。



#### devices 设备

`devices` 定义了以 `HOST_PATH:CONTAINER_PATH[:CGROUP_PERMISSIONS]` 形式为创建的容器设置的设备映射列表。

```yaml
devices:
  - "/dev/ttyUSB0:/dev/ttyUSB0"
  - "/dev/sda:/dev/xvda:rwm"
  - "/dev/net/tun"
```



#### dns 域名系统

`dns` 定义了要在容器网络接口配置中设置的自定义 DNS 服务器。它可以是单个值或列表。

```yml
dns: 8.8.8.8
```

```yaml
dns:
  - 8.8.8.8
  - 9.9.9.9
```



#### env_file 环境文件

`env_file` 属性用于指定一个或多个包含要传递给容器的环境变量的文件。

```yaml
env_file: .env
```



`env_file` 也可以是一个列表。列表中的文件从上到下进行处理。对于在两个环境文件中指定的相同变量，列表中最后一个文件的值生效。

```yml
env_file:
  - ./a.env
  - ./b.env
```



列表元素也可以声明为映射，然后可以设置一个附加属性 `required` 。这默认为 `true` 。当 `required` 设置为 `false` 并且缺少 `.env` 文件时，Compose 会默默地忽略该条目。

```yaml
env_file:
  - path: ./default.env
    required: true # default
  - path: ./override.env
    required: false
```



#### environment 环境

`environment` 属性定义在容器中设置的环境变量。 `environment` 可以使用数组或映射。任何布尔值；true、false、yes、no，都应该用引号括起来，以确保它们不会被 YAML 解析器转换为 True 或 False。

环境变量可以通过单个键（没有等于号的值）来声明。在这种情况下，Compose 依赖于您来解析值。如果未解析值，则该变量未设置，并从服务容器环境中删除。



地图语法：

```yaml
environment:
  RACK_ENV: development
  SHOW: "true"
  USER_INPUT:
```



数组语法：

```yaml
environment:
  - RACK_ENV=development
  - SHOW=true
  - USER_INPUT
```

当同时为服务设置了 `env_file` 和 `environment` 时， `environment` 设置的值具有优先权。

​	

#### expose 

`expose` 定义了 Compose 从容器暴露的（传入）端口或端口范围。这些端口必须对链接的服务可访问，但不应发布到主机。只能指定内部容器端口。

语法是 `<portnum>/[<proto>]` 或 `<startport-endport>/[<proto>]` 用于端口范围。如果没有显式设置，则使用 `tcp` 协议。

```yml
expose:
  - "3000"
  - "8000"
  - "8080-8085/tcp"
```



#### hostname 主机名

`hostname` 声明用于服务容器的自定义主机名。它必须是有效的 RFC 1123 主机名。

```
hostname: localhost
```



#### network_mode 网络模式

`network_mode` 设置服务容器的网络模式。

- `none` : 关闭所有容器网络。
- `host` : 为容器提供对主机网络接口的原始访问权限。
- `service:{name}` ：仅给予容器访问指定服务的权限。有关更多信息，请参阅容器网络。

```yaml
    network_mode: "host"
    network_mode: "none"
    network_mode: "service:[service name]"
```

注意：当设置时， `networks` 属性不允许使用，并且 Compose 会拒绝包含这两个属性的任何 Compose 文件。



#### networks 网络

`networks` 属性定义了服务容器所连接的网络，引用 `networks` 顶级元素下的条目。

```yaml
services:
  some-service:
    networks:
      - some-network
      - other-network
```



aliases 别名

aliases 在网络上声明服务的备用主机名。在同一网络上的其他容器可以使用服务名称或别名来连接到服务的一个容器。

由于 aliases 是网络范围的，相同的服 务在不同的网络上可以有不同的别名。

网络范围的别名可以被多个容器共享，甚至可以被多个服务共享。如果共享，则名称解析的确切容器无法保证。

```yaml
services:
  some-service:
    networks:
      some-network:
        aliases:
          - alias1
          - alias3
      other-network:
        aliases:
          - alias2
```



ipv4_address, ipv6_address

为在加入网络时为服务容器指定一个静态 IP 地址。

顶级网络部分中的相应网络配置必须具有一个带有子网配置的 `ipam` 属性，这些配置涵盖了每个静态地址。

```yml
services:
  frontend:
    image: example/webapp
    networks:
      front-tier:
        ipv4_address: 172.16.238.10
        ipv6_address: 2001:3984:3989::10

networks:
  front-tier:
    ipam:
      driver: default
      config:
        - subnet: "172.16.238.0/24"
        - subnet: "2001:3984:3989::/64"
```



mac_address

mac_address 设置服务容器在连接到此特定网络时使用的 MAC 地址。

```yaml
services:
  frontend:
    networks:
      front-tier:
        mac_address: 02:42:ac:11:00:02

networks:
  front-tier:
```



priority 优先级

priority 表示 Compose 按照什么顺序将服务的容器连接到其网络。如果未指定，默认值为 0。

在以下示例中，app 服务首先连接到 `app_net_1` ，因为它具有最高优先级。然后连接到 `app_net_3` ，然后连接到 `app_net_2` ，后者使用默认优先级值 0。

```yaml
services:
  app:
    image: busybox
    command: top
    networks:
      app_net_1:
        priority: 1000
      app_net_2:

      app_net_3:
        priority: 100
networks:
  app_net_1:
  app_net_2:
  app_net_3:
```



#### driver_opts

`driver_opts` 指定作为键值对传递给驱动程序的选项列表。这些选项取决于驱动程序。

```yml
services:
  app:
    networks:
      app_net:
        driver_opts:
          com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
```



#### privileged 特权

privileged 配置服务容器以提升的权限运行。支持和实际影响是平台特定的。

```yaml
services:
  privileged_service:
    image: ubuntu:latest
    privileged: true
```



#### restart 重启

restart 定义平台在容器终止时应用的策略。

- no ：默认重启策略。在任何情况下都不会重启容器。
- always : 策略始终重启容器，直到其被移除。
- on-failure[:max-retries] : 如果退出代码表示错误，则策略重启容器。可选地，限制 Docker 守护程序尝试重启的次数。
- unless-stopped : 无论退出代码如何，该策略都会重新启动容器，但在服务停止或移除时停止重新启动。

```yaml
    restart: "no"
    restart: always
    restart: on-failure
    restart: on-failure:3
    restart: unless-stopped
```



#### volumes 卷

`volumes` 属性定义了可被服务容器访问的挂载主机路径或命名卷。您可以使用 `volumes` 来定义多种类型的挂载； `volume` ， `bind` ， `tmpfs` ，或 `npipe` 。

如果挂载是主机路径并且仅由单个服务使用，可以作为服务定义的一部分进行声明。要在多个服务之间重用卷，必须在 `volumes` 顶级元素中声明命名卷。



短语法

短语法使用带有冒号分隔值的单个字符串来指定卷挂载（ `VOLUME:CONTAINER_PATH` ）或访问模式（ `VOLUME:CONTAINER_PATH:ACCESS_MODE` ）。

- `VOLUME` ：可以是托管容器平台上的主机路径（绑定挂载）或卷名称。
- `CONTAINER_PATH` : 卷在容器中挂载的路径。
- `ACCESS_MODE` : 由逗号分隔的 `,` 选项列表：
  - `rw` : 读写访问。如果未指定任何选项，则这是默认值。
  - `ro` ：只读访问。
  - `z` : SELinux 选项，表示绑定挂载的主机内容在多个容器之间共享。
  - `Z` : SELinux 选项，表示绑定挂载的主机内容是私有的，不对其他容器共享。



长语法

- `type` : 挂载类型。可以是 `volume` ， `bind` ， `tmpfs` ， `npipe` 或 `cluster` 。
- `source` : 挂载的来源，主机上的一个路径，用于绑定挂载，或者在顶级 `volumes` 键中定义的卷的名称。对于 tmpfs 挂载不适用。
- `target` : 卷在容器中挂载的路径。
- `read_only` : 设置为只读卷的标志。
- `bind` : 用于配置附加的绑定选项：
  - `propagation` : 用于绑定的传播模式
  - `create_host_path` : 如果主机上的源路径处没有任何内容，则创建一个目录。如果路径处已有内容，Compose 不执行任何操作。这通过短语法自动实现，以向后兼容 `docker-compose` 传统版本。
  - `selinux` : SELinux 重新标记选项 `z` （共享）或 `Z` （私有）
- `volume` ：配置额外的卷选项：
  - `nocopy` : 禁用从容器复制数据的标志，当创建卷时。
  - `subpath` : 在卷中挂载的路径，而不是卷的根目录。
- `tmpfs` : 配置额外的 tmpfs 选项：
  - `size` : 以字节为单位的 tmpfs 挂载大小（可以是数字或字节单位）。
  - `mode` : 作为八进制数字的 Unix 权限位的 tmpfs 挂载的文件模式。在 Docker Compose 版本 2.14.0 中引入。
- `consistency` : 挂载的一致性要求。可用值取决于平台。





以下示例显示了 `backend` 服务使用的命名卷（ `db-data` ）和为单个服务定义的绑定挂载。

```yml
services:
  backend:
    image: example/backend
    volumes:
      - /docker/nginx/:/etc/nginx,rw
      - /docker/html/:/var/www/html/,ro
      - type: volume
        source: db-data
        target: /data
        volume:
          nocopy: true
          subpath: sub
      - type: bind
        source: /var/run/postgres/postgres.sock
        target: /var/run/postgres/postgres.sock

volumes:
  db-data:
```



#### volumes_from 从卷

`volumes_from` 挂载来自另一个服务或容器的所有卷。您可以选择指定只读访问 `ro` 或读写 `rw` 。如果未指定访问级别，则使用读写访问。

您还可以使用 `container:` 前缀从不受 Compose 管理的容器挂载卷。

```yaml
volumes_from:
  - service_name
  - service_name:ro
  - container:container_name
  - container:container_name:rw
```



#### working_dir

working_dir 覆盖由镜像指定的容器的工作目录，例如 Dockerfile 的 WORKDIR 。

```yaml
working_dir: /etc/nginx/
```



### network

顶级 `networks` 元素可以让您配置可以在多个服务之间重用的命名网络。

默认情况下，Compose 为您的应用程序设置一个网络。每个服务的容器会加入默认网络，并且在该网络上的其他容器中可达，并且可以通过服务的名称发现。



#### 基本示例

在以下示例中，在运行时创建了 front-tier 和 back-tier 网络，并将 frontend 服务连接到 front-tier 和 back-tier 网络。

```yaml
services:
  frontend:
    image: example/webapp
    networks:
      - front-tier
      - back-tier

networks:
  front-tier:
  back-tier:
```



#### driver 驱动程序

driver 指定应为此网络使用哪个驱动程序。如果平台不支持该驱动程序，Compose 将返回错误。

```yml
networks:
  db-data:
    driver: bridge
```

选项：bridge、host、overlay、ipvlan、macvlan、none



#### driver_opts

driver_opts 指定作为键值对传递给驱动程序的选项列表。这些选项取决于驱动程序。

```yaml
networks:
  frontend:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: "frontend"
      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
```



#### attachable 可附加的

如果 attachable 设置为 true ，则独立容器应能够附加到此网络，除了服务。如果一个独立容器附加到网络，它可以与服务和其他也附加到网络的独立容器进行通信。

```yaml
networks:
  mynet1:
    driver: overlay
    attachable: true
```



#### enable_ipv6 启用 IPv6

`enable_ipv6` 启用 IPv6 网络。例如，请参阅创建 IPv6 网络的步骤四。



#### external 外部

如果设置为 `true` ：

- `external` 指定此网络的生命周期在应用程序之外进行维护。Compose 不会尝试创建这些网络，并在不存在这些网络时返回错误。
- 除名称外，所有其他属性都无关紧要。如果 Compose 检测到任何其他属性，它会将 Compose 文件视为无效。



在下面的示例中， `proxy` 是通往外部世界的网关。Compose 不是尝试创建一个网络，而是查询平台是否存在一个名为 `outside` 的现有网络，并将 `proxy` 服务的容器连接到该网络。

```yaml
services:
  proxy:
    image: example/proxy
    networks:
      - outside
      - default
  app:
    image: example/app
    networks:
      - default

networks:
  outside:
    external: true
```



#### ipam

ipam 指定一个自定义的 IPAM 配置。这是一个具有多个属性的对象，每个属性都是可选的：

- `driver` ：自定义的 IPAM 驱动，而不是默认的。
- `config` ：一个包含零个或多个配置元素的列表，每个元素包含一个：
  - `subnet` : 代表网络段的 CIDR 格式的子网
  - `ip_range` : 用于分配容器 IP 的 IP 范围
  - `gateway` : 主子网的 IPv4 或 IPv6 网关
  - `aux_addresses` : 网络驱动使用的辅助 IPv4 或 IPv6 地址，作为从主机名到 IP 的映射
- `options` : 作为键值映射的驱动程序特定选项。

```yml
networks:
  mynet1:
    ipam:
      driver: default
      config:
        - subnet: 172.28.0.0/16
          ip_range: 172.28.5.0/24
          gateway: 172.28.5.254
          aux_addresses:
            host1: 172.28.1.5
            host2: 172.28.1.6
            host3: 172.28.1.7
      options:
        foo: bar
        baz: "0"
```



#### internal 内部

默认情况下，Compose 为网络提供外部连接。 `internal` ，当设置为 `true` 时，允许您创建一个与外部隔离的网络。



#### name 名称

`name` 为网络设置自定义名称。name 字段可用于引用包含特殊字符的网络。该名称将直接使用，不会与项目名称进行作用域限定。

```yml
networks:
  network1:
    name: my-app-net
```



还可以与 `external` 属性结合使用，以定义 Compose 应检索的平台网络，通常通过使用参数，以便 Compose 文件不需要硬编码运行时特定的值：

```yml
networks:
  network1:
    external: true
    name: "${NETWORK_ID}"
```



### volumes

volumes是由容器引擎实现的持久数据存储。Compose 提供了一种中立的方式来让服务挂载数据卷，并提供配置参数将它们分配给基础设施。



#### 基础示例

以下示例展示了两个服务的设置，其中一个数据库的数据目录作为卷与另一个服务共享，命名为 db-data ，以便可以定期备份。

```yaml
services:
  backend:
    image: example/database
    volumes:
      - db-data:/etc/data

  backup:
    image: backup-service
    volumes:
      - db-data:/var/lib/backup/data

volumes:
  db-data:
```

`db-data` 卷在 `/var/lib/backup/data` 和 `/etc/data` 容器路径上挂载，分别用于备份和后端。

运行 `docker compose up` 会创建该卷（如果尚未存在）。否则，将使用现有卷，并且如果在 Compose 外手动删除该卷，它将被重新创建。



#### driver 驱动程序

指定应使用哪个卷驱动程序。如果未找到该驱动程序，Compose 将返回错误并且不会部署应用程序。

```yaml
volumes:
  db-data:
    driver: foobar
```



#### driver_opts

driver_opts 指定要传递给此卷驱动程序的选项列表，这些选项以键值对形式表示。这些选项取决于驱动程序。

```yaml
volumes:
  example:
    driver_opts:
      type: "nfs"
      o: "addr=10.40.0.199,nolock,soft,rw"
      device: ":/docker/example"
```



#### external 外部

如果设置为 true ：

- `external` 指定该卷已在平台上存在，并且其生命周期由应用程序之外的其他地方管理。在这种情况下，Compose 不会创建该卷，并在卷不存在时返回错误。
- 除 `name` 之外的所有其他属性都是无关的。如果 Compose 检测到任何其他属性，它会拒绝该 Compose 文件，认为其无效。



在下面的示例中，而不是尝试创建一个名为 `{project_name}_db-data` 的卷，Compose 会查找一个简单的名为 `db-data` 的现有卷，并将其挂载到 `backend` 服务的容器中。

```yml
services:
  backend:
    image: example/database
    volumes:
      - db-data:/etc/data

volumes:
  db-data:
    external: true
```



name 名称

name 为卷设置自定义名称。name 字段可用于引用包含特殊字符的卷。名称将直接使用，不会与堆栈名称进行作用域限定。

```yaml
volumes:
  db-data:
    name: "my-app-data"
```



这使得可以将此查找名称作为 Compose 文件的参数，以便卷的模型 ID 是硬编码的，但平台上的实际卷 ID 在部署时在运行时设置。

例如，如果 DATABASE_VOLUME=my_volume_001 在您的 .env 文件中：

```yaml
volumes:
  db-data:
    name: ${DATABASE_VOLUME}
```



运行 docker compose up 使用名为 my_volume_001 的卷。

它也可以与 external 属性一起使用。这意味着用于在平台上查找实际卷的名称与在 Compose 文件中引用该卷的名称分开设置：

```yaml
volumes:
  db-data:
    external: true
    name: actual-name-of-volume
```

