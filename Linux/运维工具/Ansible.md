# Ansible

## 核心概念

Ansible 简介

Ansible 提供开源自动化解决方案，能够降低复杂度并在任意环境中运行。使用 Ansible 几乎可以自动化任何任务。以下是 Ansible 的一些常见应用场景：

- 消除重复并简化工作流程
- 管理和维护系统配置
- 持续部署复杂软件
- 执行零停机滚动更新



Ansible 通过称为 playbook 的简单易读脚本来自动化任务。您在 playbook 中声明本地或远程系统的期望状态，Ansible 会确保系统始终保持该状态。

作为自动化技术，Ansible 的设计遵循以下原则：

Agent-less architecture（无代理架构） 
	低维护开销，因为它避免在整个 IT 基础设施中安装额外的软件。

Simplicity（简洁性） 
	自动化 Playbook 使用简单的 YAML 语法编写，代码如同文档般易读。Ansible 也是去中心化的，使用现有的操作系统凭据来访问远程机器。

Scalability and flexibility（可扩展性和灵活性） 
	通过支持各种操作系统、云平台和网络设备的模块化设计，可以轻松快速地扩展自动化系统。

Idempotence and predictability（幂等性和可预测性） 
	当系统处于你的 Playbook 所描述的状态时，即使 Playbook 多次运行，Ansible 也不会做任何改变。



这些概念是所有 Ansible 使用场景的通用基础。在使用 Ansible 或阅读其官方文档之前，应首先理解这些术语。



**控制节点 (Control Node)**

**控制节点**是指运行 Ansible 命令行工具（如 `ansible-playbook`、`ansible`、`ansible-vault` 等）的计算机系统。任何满足 Ansible 软件依赖性要求的计算机均可作为控制节点，包括笔记本电脑、共享桌面或服务器。Ansible 也可以在称为**执行环境 (Execution Environments)** 的容器化环境中运行。尽管可以部署多个控制节点，但 Ansible 本身不提供跨节点的协调机制。



**被管理节点 (Managed Nodes)**

**被管理节点**，亦称为**主机 (hosts)**，是 Ansible 操作的目标设备。这些设备可以是服务器、网络设备或任何其他计算机系统。通常情况下，Ansible 代理程序不会安装在被管理节点上。一个例外是使用 `ansible-pull` 模式，但这是一种非常规且不推荐的配置方法。标准的 Ansible 架构是无代理 (agent-less) 的，通过 SSH（针对类 UNIX 系统）或 WinRM（针对 Windows 系统）等标准协议进行通信和管理。



**清单 (Inventory)**

**清单**是由一个或多个**清单源 (inventory sources)** 提供的被管理节点的列表。清单文件不仅定义了被管理节点，还可以为每个节点指定特定的连接信息，例如 IP 地址、端口或连接凭证。此外，清单还用于将被管理节点分配到不同的**组 (groups)** 中，这使得在 Play 中能够批量选择节点，并对组内所有节点统一应用变量。清单源文件有时也被称为**主机文件 (hostfile)**。



**Playbooks**

**Playbooks** 是包含一个或多个 **Play** 的文件，是 Ansible 执行操作的蓝图。这个术语既指代 Ansible 的一个执行概念，也指代 `ansible-playbook` 命令所操作的物理文件。Playbook 使用 YAML 格式编写，具有高可读性，易于编写、共享和理解。



**Play**

**Play** 是 Ansible 执行的基本单元和主要上下文，其核心功能是将一组被管理节点（通过 `hosts` 指令指定）映射到一组有序的**任务 (Tasks)**。一个 Play 内部可以定义变量、角色 (Roles) 和一个有序的任务列表，并且可以被重复执行。其本质上是在所映射的主机和任务之上构成一个隐式循环，并定义了这些操作的迭代方式。



**角色 (Roles)**

**Roles** 是一种用于组织和复用 Ansible 内容（包括任务、处理器、变量、插件、模板和文件）的特定目录结构。它是一种有限分发格式，旨在封装一个特定的功能或组件，以便在不同的 Play 中重复使用。要使用角色中定义的任何资源，该角色必须被显式地导入到 Play 中。



**任务 (Tasks)**

**Taks** 是应用于被管理主机的单个**动作 (action)** 的定义。每个任务都调用一个**模块 (Module)** 并传入相应的参数来执行具体操作。用户可以使用 `ansible` 或 `ansible-console` 命令以 ad-hoc（即席）方式执行单个任务，这两种方式都会在后台创建一个临时的虚拟 Play 来完成该任务的执行。



**处理器 (Handlers)**

**处理器**是一种特殊形式的任务。它的独特性在于，它仅在被前一个任务**通知 (notify)** 时才会执行，并且该通知操作仅当源任务的执行状态为 **`changed`** 时才会触发。处理器通常用于定义在配置发生变更后才需要执行的服务重启、系统重载等操作。



**模块 (Modules)**

**模块**是 Ansible 复制到每个被管理节点并执行的代码或二进制文件，用于完成每个任务中定义的具体动作。每个模块都具有特定的用途，例如在特定类型的数据库上管理用户，或在特定类型的网络设备上管理 VLAN 接口。您可以在一个任务中调用单个模块，或在一个 Playbook 中调用多个不同的模块。Ansible 模块被组织在**集合 (Collections)** 中。



**插件 (Plugins)**

**插件**是用于扩展 Ansible 核心功能的代码片段。插件的类型多种多样，它们可以控制 Ansible 如何连接到被管理节点（**连接插件, connection plugins**）、在数据处理过程中操作数据（**过滤器插件, filter plugins**），甚至可以控制控制台输出的格式与内容（**回调插件, callback plugins**）。



**集合 (Collections)**

**集合**是 Ansible 内容的一种分发格式，其内部可以包含**Playbooks**、**Roles**、模块和插件。您可以通过 Ansible Galaxy 这个公共内容仓库来安装和使用社区或官方发布的集合。集合中的各种资源（如模块、角色）可以被独立且离散地调用。



## 入门

开始使用 Ansible 实现自动化



### Install

安装 Ansible（在 RedHat10 系统上）

```
dnf -y install ansible-core
```



在您的文件系统中创建一个项目文件夹。

```
mkdir ansible_task && cd ansible_task
```



### inventory

创建**清单（inventory）文件**

**清单（inventory）**将被管理节点的信息列出在文件中，为 Ansible 提供系统信息和网络位置。通过使用清单文件，Ansible 可以用单一命令管理大量主机。

要完成以下步骤，需要至少一个被管理节点的 IP 地址或完全限定域名(FQDN)。必须确保将公钥 SSH 添加到每个主机的 **authorized_keys **文件中。



在 **ansible_task** 文件夹中创建 **inventory.ini** 文件。在文件中添加一个新的 `[myhosts]` 组，并为每个主机系统指定 IP 地址或完全限定域名(FQDN)。

```
[myhosts]
10.14.0.102
10.14.0.103
```



验证 inventory

```
ansible-inventory -i inventory.ini --list
```

```
{
    "_meta": {
        "hostvars": {}
    },
    "all": {
        "children": [
            "ungrouped",
            "myhosts"
        ]
    },
    "myhosts": {
        "hosts": [
            "10.14.0.102",
            "10.14.0.103"
        ]
    }
}

```



对 inventory 中的 `myhosts` 组执行 ping 操作。

```
ansible myhosts -m ping -i inventory.ini
```

```
10.14.0.102 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3"
    },
    "changed": false,
    "ping": "pong"
}
10.14.0.103 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3"
    },
    "changed": false,
    "ping": "pong"
}

```



在 Ansible 中，当你执行命令去管理远程服务器（即被管理节点）时，默认会尝试使用与你当前在本地（即控制节点）登录的用户名相同的账户进行连接。

如果控制节点与被管理节点的用户名不同，请使用 `ansible` 命令传递 `-u` 选项。



INI 或 YAML 格式的 inventory 

可以使用在 `INI` 文件或 `YAML` 格式创建 inventory。在大多数情况下（仅管理少量主机时）， `INI` 文件更直观且易于阅读。



例如，下面这个 YAML 格式的 inventory 文件，它的作用和之前在 `inventory.ini` 文件中，用 `ansible_host` 字段指定主机地址的方式是**等效的**。

```yaml
myhosts:
  hosts:
    my_host_01:
      ansible_host: 192.0.2.50
    my_host_02:
      ansible_host: 192.0.2.51
    my_host_03:
      ansible_host: 192.0.2.52
```



**构建 inventory 的技巧**

- 确保组名**具有意义且唯一**。组名还**区分大小写**。
- 避免在组名中使用空格、连字符和前导数字（应使用 `floor_19` 而非 `19th_floor` ）。
- 根据主机的**功能（What）、位置（Where）和时间（When）**对清单中的主机进行逻辑分组。
  - **What**：根据拓扑结构对主机进行分组，例如：db、web、leaf、spine。
  - **Where**：按地理位置对主机进行分组，例如：数据中心、区域、楼层、建筑物。
  - **When**：按阶段对主机进行分组，例如：开发、测试、预发布、生产环境。



### playbook

**创建 playbook**

**Playbook** 是自动化蓝图，采用 YAML 格式，Ansible 使用它来部署和配置被管理节点。



**Playbook**
	一系列 **play** 的列表，它定义了 Ansible 为了实现总体目标而从上到下执行操作的顺序。 

**Play**
	一个有序的 **task** 列表，它映射到清单（inventory）中的被管理节点。 

**Task**
	对单个 **module** 的引用，它定义了 Ansible 执行的操作。 

**Module**
	Ansible 在被管理节点上运行的代码或二进制文件单元。 Ansible 模块被分组在集合（collections）中，每个模块都有一个完全限定集合名称（FQCN）。





在 ansible_task 目录中，创建一个名为 `playbook.yaml` 的文件，其内容如下：

```
- name: My first play
  hosts: myhosts
  tasks:
    - name: Ping my hosts
      ansible.builtin.ping:
    - name: Print message
      ansible.builtin.debug:
        msg: Hello world
```



运行 playbook

```
ansible-playbook -i inventory.ini playbook.yaml
```

Ansible 返回以下输出：

```
PLAY [My first play] ****************************************************************************************************************************************

TASK [Gathering Facts] **************************************************************************************************************************************
ok: [10.14.0.102]
ok: [10.14.0.103]

TASK [Ping my hosts] ****************************************************************************************************************************************
ok: [10.14.0.103]
ok: [10.14.0.102]

TASK [Print message] ****************************************************************************************************************************************
ok: [10.14.0.102] => {
    "msg": "Hello world"
}
ok: [10.14.0.103] => {
    "msg": "Hello world"
}

PLAY RECAP **************************************************************************************************************************************************
10.14.0.102                : ok=3    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
10.14.0.103                : ok=3    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
```



## inventory



## playbook

Ansible Playbook 提供了一个可重复、可重用且简洁的配置管理与多机部署系统，是部署复杂应用程序的理想选择。如果您需要使用 Ansible 多次执行同一任务，最佳实践便是编写一个 Playbook，并将其纳入版本控制系统。之后，您便可以利用此 Playbook 推送新配置或验证远程系统的当前配置状态。Playbook 采用 YAML 格式编写，语法极其精简。



**Playbook 含义**

一个 Playbook 由一个或多个按顺序排列的 “play” 组成。“Playbook” 和 “play” 这两个术语源自体育界的类比。每个 play 负责执行 Playbook 总体目标的一部分，它包含一个或多个任务，而每个任务都会调用一个 Ansible 模块。



**Playbook 执行顺序**

Playbook 的执行顺序是**从上至下**。在每个 play 内部，任务也同样**从上至下**依次执行。包含多个 play 的 Playbook 能够编排复杂的多机部署，例如，一个 play 针对 Web 服务器，另一个针对数据库服务器，第三个则作用于网络基础设施。

每个 play 至少需要定义以下两个要素：

1. **目标受管节点**，通过 pattern（模式）来指定。
2. **至少一个待执行的任务**。



对于 Ansible 2.10 及更高版本，强烈建议在 Playbook 中使用**完全限定集合名称 (FQCN)**。因为不同的集合 (collection) 可能包含同名模块，使用 FQCN 可以确保您选用的是正确的模块。例如，`user` 模块。更多信息请参见**在 Playbook 中使用集合**。

在以下示例中，第一个 play 的目标是 Web 服务器，第二个 play 的目标是数据库服务器。

```yaml
- name: 更新 Web 服务器
  hosts: webservers
  remote_user: root

  tasks:
    - name: 确保 apache 为最新版本
      ansible.builtin.yum:
        name: httpd
        state: latest

    - name: 写入 apache 配置文件
      ansible.builtin.template:
        src: /srv/httpd.j2
        dest: /etc/httpd.conf

- name: 更新数据库服务器
  hosts: databases
  remote_user: root

  tasks:
    - name: 确保 postgresql 为最新版本
      ansible.builtin.yum:
        name: postgresql
        state: latest

    - name: 确保 postgresql 服务已启动
      ansible.builtin.service:
        name: postgresql
        state: started
```

*除了 `hosts` 和 `tasks`，您的 Playbook 还可以包含更多元素。例如，上述 Playbook 为每个 play 设置了 `remote_user`，该用户是 SSH 连接所使用的账户。您还可以在 playbook、play 或 task 级别添加其他 **Playbook 关键字**，以控制 Ansible 的行为。这些关键字可以用于管理连接插件、是否使用权限提升、如何处理错误等。为了适应多样的环境，许多参数也可以通过命令行标志、Ansible 配置或 Inventory 来设置。理解这些不同数据源的**优先级规则**，对于您扩展 Ansible 生态系统至关重要。*



**任务执行**

默认情况下，Ansible 会针对主机模式匹配到的所有机器，**按顺序、逐一执行每个任务**。每个任务都以特定的参数调用一个模块。当一个任务在所有目标机器上执行完毕后，Ansible 才会执行下一个任务。您可以使用**策略 (strategies)** 来改变这种默认行为。在同一个 play 中，Ansible 会对所有主机应用相同的任务指令。如果某个任务在某台主机上执行失败，Ansible 会将该主机从后续任务的执行队列中移除。

当您运行 Playbook 时，Ansible 会返回有关连接的信息、所有 play 和 task 的名称、每个任务在各台机器上的成功或失败状态，以及任务是否对机器造成了更改。在 Playbook 执行的最后，Ansible 会提供一份摘要，总结目标节点的执行情况。常规失败和致命的“无法访问”通信尝试会分开统计。



**期望状态与幂等性**

大多数 Ansible 模块都会**检查系统的当前状态是否已达到期望的最终状态**。如果已达到，模块将直接退出，不执行任何操作。重复执行任务并不会改变最终结果。具备这种特性的模块被称为“**幂等的 (idempotent)**”。无论您运行一个 Playbook 一次还是多次，其结果都应保持一致。然而，并非所有 Playbook 和模块都天然具备幂等性。如果您不确定，请先在沙箱环境中测试您的 Playbook，然后再在生产环境中多次运行。



### 语法

Ansible Playbook 配置文件中的语法层级

一个 Ansible Playbook 是一个 YAML 文件，其结构具有清晰的层级关系，从宏观到微观依次为：**Playbook -> Play -> Task / handler -> Module**。



**Task 和 Handler**

**Task 和 Handler** 在 Playbook 的语法结构上是**平级**的，但在执行逻辑上是**调用与被调用**的触发关系。

```yaml
- name: 一个演示 Play
  hosts: webservers
  become: yes

  # --- Task 块 ---
  # 定义了主要执行流程，会按顺序执行
  tasks:
    - name: 确保 httpd 软件包已安装
      ansible.builtin.yum:
        name: httpd
        state: present

    - name: 复制 httpd 配置文件
      ansible.builtin.template:
        src: httpd.conf.j2
        dest: /etc/httpd/conf/httpd.conf
      notify: Restart httpd service  # <-- 在这里“通知”Handler

  # --- Handler 块 ---
  # 与 tasks 块平级，定义了被动响应的任务
  handlers:
    - name: Restart httpd service   # <-- 这个 name 被 notify 引用
      ansible.builtin.service:
        name: httpd
        state: restarted
```

这个 Ansible Play 的主要作用是在`webservers`组中的所有服务器上，自动化地安装并配置 Apache 网页服务器（httpd）。

它的执行流程如下：

1. 首先，它会检查服务器上是否已经安装了 `httpd` 软件包，如果没有，就会自动安装。
2. 接着，它会将一个本地的配置文件模板（`httpd.conf.j2`）部署到服务器的指定位置。
3. 最关键的一步是，如果在第二步中配置文件发生了实际的变动，那么在整个 Play 执行的最后，它会自动触发一个操作来重启 Apache 服务，以确保新的配置生效。如果配置文件没有变化，服务则不会被重启。



#### Playbook

Playbook 是最高层级，代表整个 YAML 文件。一个 Playbook 文件本质上是一个列表 (list)，列表中的每一个元素都是一个 **Play**。因此，您可以在一个文件中定义多个 Play，Ansible 会按照它们在文件中的顺序依次执行。

**语法特点**：

- 文件以 `.yaml` 或 `.yml` 结尾。
- 文件的顶层是一个 YAML 列表，每个列表项由一个连字符 (`-`) 开头。

```yaml
# 这是一个 Playbook 文件，它包含两个 Play
---
# 第一个 Play 开始
- name: 配置 Web 服务器
  hosts: webservers
  # ... Play 的具体内容

# 第二个 Play 开始
- name: 配置数据库服务器
  hosts: dbservers
  # ... Play 的具体内容
```



#### Play 

Play 是 Playbook 的核心组成部分，它定义了一次完整的自动化执行过程。一个 Play 的核心作用是**将一组主机（从 Inventory 中选取）与一组任务（Tasks）进行映射**。

Play 是一个 YAML 字典 (dictionary)，包含一系列的键值对，我们称之为“指令”(Directives)。



##### name

`name`: 为 Play 提供一个人类可读的描述性名称。这个名称会显示在 `ansible-playbook` 命令的输出中，用于清晰地标识当前正在执行的 Play。

```yaml
- name: This play configures the web servers
  hosts: webservers
  # ...
```



##### hosts

`hosts`: 定义此 Play 将要应用到的一组或多组主机。这是 Play 中必不可少的部分，它告诉 Ansible 操作的目标是谁。其值可以是一个主机名、IP 地址、清单中的组名，或者多个组的组合。

```
- name: Update web and database servers
  hosts: webservers:dbservers
  # ...
```



##### gather_facts

`gather_facts`: 一个布尔值，用于控制是否在执行任务前收集有关远程主机的信息（称为 "facts"）。这些信息包括 IP 地址、操作系统、内存等，可以在后续任务中作为变量使用。默认为 `true`。

```
- name: A play that runs faster without facts
  hosts: all
  gather_facts: false
  # ...
```



##### pre_tasks

`pre_tasks`: 定义一个任务列表，这些任务会在 `roles` 执行之前运行。它通常用于执行一些准备工作，无论后续 `roles` 中定义了什么内容，这些任务都会首先被执行。

```
- name: A play with setup tasks
  hosts: all
  pre_tasks:
    - name: Ensure firewalld is running
      ansible.builtin.service:
        name: firewalld
        state: started
  # ...
```



##### tasks

`tasks`: 定义此 Play 的主要任务列表。这是 Play 的核心部分，包含了所有需要按顺序执行的自动化操作，例如安装软件、复制文件、启动服务等。

```
- name: A play with a main task
  hosts: all
  tasks:
    - name: Install the latest version of Apache
      ansible.builtin.yum:
        name: httpd
        state: latest
```



##### post_tasks

`post_tasks`: 定义一个任务列表，这些任务会在 `roles` 和 `tasks` 都执行完毕之后运行。它常用于执行清理工作或验证操作，确保无论主要任务执行了什么，收尾工作都能完成。

```
- name: A play with cleanup tasks
  hosts: all
  post_tasks:
    - name: Clean yum metadata
      ansible.builtin.command: yum clean all
      args:
        warn: false
```



##### roles

`roles`: 指定一个要在此 Play 中执行的角色列表。Roles 是一种组织和复用 Ansible 内容（任务、处理器、变量等）的机制，使用 `roles` 可以让 Playbook 结构更清晰、更模块化。

```
- name: A play that uses a role
  hosts: webservers
  roles:
    - common
    - nginx
```



##### handlers

`handlers`: 定义一个处理器列表。处理器是特殊类型的任务，它们只有在被 `tasks` 中的 `notify` 指令触发时才会被执行，并且会在所有 `tasks` 完成后统一执行。通常用于响应配置变化（如重启服务）。

```
- name: A play with a handler
  hosts: webservers
  handlers:
    - name: Restart nginx
      ansible.builtin.service:
        name: nginx
        state: restarted
```



##### vars

`vars`: 在 Play 级别定义变量。在这里定义的变量可以被此 Play 中的所有任务、处理器和模板使用。这是一种直接在 Playbook 中设置变量的便捷方式。

```
- name: A play with variables
  hosts: all
  vars:
    package_name: httpd
    service_name: httpd
  # ...
```



##### vars_files

`vars_files`: 指定一个或多个包含变量的外部文件。这有助于将变量与 Playbook 的逻辑分离，使配置更易于管理。文件中定义的变量将对当前 Play 可用。

```
- name: A play that loads variables from a file
  hosts: all
  vars_files:
    - /path/to/vars.yaml
    - /path/to/another_vars.yaml
```



##### vars_prompt

`vars_prompt`: 在运行 Playbook 时向用户提示输入信息，并将其值存为变量。这对于需要交互式输入敏感信息（如密码）或动态配置的场景非常有用。

```
- name: A play that prompts for user input
  hosts: all
  vars_prompt:
    - name: db_password
      prompt: "Please enter the database password"
      private: yes
```



##### connection

`connection`: 指定 Ansible 连接到被管理节点时使用的连接插件。默认是 `ssh`。其他常见的值包括 `local`（在控制节点本地执行）、`docker`（连接到 Docker 容器）和 `winrm`（用于 Windows 主机）。

```
- name: A play that runs locally
  hosts: 127.0.0.1
  connection: local
  # ...
```



##### port

`port`: 指定连接到被管理节点时使用的端口号。默认情况下，SSH 连接使用 22 端口。如果您的主机使用非标准端口，可以在这里指定。

```
- name: A play connecting to a custom port
  hosts: myhost.example.com
  port: 2222
  # ...
```



##### remote_user

`remote_user`: 指定 Ansible 在连接到被管理节点时使用的用户名。这会覆盖清单文件或配置文件中定义的默认用户。

```
- name: A play running as the 'admin' user
  hosts: all
  remote_user: admin
  # ...
```



##### become

`become`: 一个布尔值，设置为 `true` 时表示需要进行权限提升。这等同于在命令行中使用 `sudo` 或 `su` 等命令，用于执行需要更高权限（通常是 root）的任务。

```
- name: A play that requires root privileges
  hosts: all
  become: true
  # ...
```



##### become_user

`become_user`: 指定要提升到的目标用户名。默认是 `root`。当您需要以某个特定的非 root 超级用户身份执行任务时，可以使用此指令。

```
- name: A play becoming the 'oracle' user
  hosts: dbservers
  become: true
  become_user: oracle
  # ...
```



##### become_method

`become_method`: 指定权限提升的方法。默认是 `sudo`。其他可能的值包括 `su`、`pbrun`、`enable` 等，具体取决于目标系统的配置和可用的权限提升工具。

```
- name: A play using 'su' for privilege escalation
  hosts: all
  become: true
  become_method: su
  # ...
```



##### check_mode

`check_mode`: 启用检查模式。设置为 `true` 时，Ansible 不会对远程系统进行任何实际更改，而是报告它将会做出哪些更改。这对于在部署前进行演练和验证非常有用。

```
- name: A play running in check mode
  hosts: all
  check_mode: true
  # ...
```



##### diff

`diff`: 一个布尔值，当设置为 `true` 时，对于那些管理文件的模块（如 `template`、`copy`），如果文件内容发生变化，Ansible 会显示新旧文件之间的差异（diff）。这对于审计配置变更非常有用。

```
- name: A play that shows file differences
  hosts: all
  diff: true
  # ...
```



##### serial

`serial`: 控制 Play 在多少台主机上并行执行。默认情况下，Ansible 会在所有匹配的主机上同时执行任务。通过 `serial`，可以实现滚动更新，例如一次只在一台主机或一定比例的主机上执行。

```
- name: A rolling update play
  hosts: webservers
  serial: 1 # one host at a time
  # ...
```



##### strategy

`strategy`: 定义任务在主机组上的执行策略。默认是 `linear`，即在一个任务完成于所有主机后，再开始下一个任务。`free` 策略则允许每台主机尽快独立地完成所有任务，不受其他主机进度的影响。

```
- name: A play with the 'free' strategy
  hosts: all
  strategy: free
  # ...
```



##### any_errors_fatal

`any_errors_fatal`: 一个布尔值，当设置为 `true` 时，只要在此 Play 的任何一台主机上发生任何任务失败，就会立即中止整个 Playbook 的执行。这对于关键的、不容许部分失败的部署非常重要。

```
- name: A critical play where any error is fatal
  hosts: all
  any_errors_fatal: true
  # ...
```



##### max_fail_percentage

`max_fail_percentage`: 设置一个允许任务失败的主机百分比。如果失败的主机数量超过这个百分比，整个 Play 就会中止。这为批量操作提供了一定的容错能力。

```
- name: A play that tolerates some failures
  hosts: all
  max_fail_percentage: 30
  # ...
```



##### max_fail_percentage

`max_fail_percentage`: 设置一个允许任务失败的主机百分比。如果失败的主机数量超过这个百分比，整个 Play 就会中止。这为批量操作提供了一定的容错能力。

```
- name: A play that tolerates some failures
  hosts: all
  max_fail_percentage: 30
  # ...
```



##### tags

tags: 为 Play 中的所有任务、角色等内容应用一个或多个标签。通过在命令行中使用 --tags 或 --skip-tags 选项，可以只运行或跳过带有特定标签的部分，从而更灵活地控制 Playbook 的执行范围。

```
- name: A tagged play
  hosts: all
  tags:
    - configuration
    - packages
  # ...
```



##### collections

`collections`: 定义一个此 Play 依赖的 Ansible Collection 列表。在这里声明后，您在 Play 中调用模块、角色等内容时就可以使用短名称，而无需写出完整的 FQCN (Fully Qualified Collection Name)。

```
- name: A play using collections
  hosts: all
  collections:
    - community.general
  tasks:
    - name: Use a module from the collection
      ufw: # Instead of community.general.ufw
        rule: allow
        port: '80'
        proto: tcp
```



#### Task

task 是 Playbook 中最基本的工作单元，定义了一个独立的、需要执行的**原子操作**。例如，“安装一个软件包”、“启动一个服务”或“复制一个文件”。一个 Play 中的所有任务会按照定义的顺序在所有目标主机上执行。

Task 是 `tasks` 列表中的一个字典。



##### name

`name`: 为任务提供一个人类可读的描述性名称。这个名称会在 `ansible-playbook` 运行时清晰地显示出来，是调试和理解 Playbook 执行流程的最重要元素之一。

```
- name: Ensure the httpd package is installed
  ansible.builtin.yum:
    name: httpd
    state: present
```



##### Module Call

模块调用: 每个任务的核心是调用一个 Ansible 模块。通过指定模块名称（例如 `ansible.builtin.yum`）并为其提供所需的参数（例如 `name` 和 `state`），来定义该任务需要执行的具体操作。

```
- name: Start the httpd service
  ansible.builtin.service: # <-- 模块调用
    name: httpd           # <-- 模块参数
    state: started
```



##### when

`when`: 定义一个条件表达式。只有当该表达式的计算结果为 `true` 时，当前任务才会被执行，否则将被跳过。这使得任务可以根据变量、facts 或前一个任务的结果来条件性地执行。

```
- name: Shutdown Debian family systems
  ansible.builtin.command: /sbin/shutdown -t now
  when: ansible_os_family == "Debian"
```



##### loop

`loop`: 对一个列表进行迭代，为列表中的每一项执行一次当前任务。在任务内部，可以使用 `item` 变量来引用列表中的当前项。这是处理重复性操作的标准方式。

```
- name: Create multiple user accounts
  ansible.builtin.user:
    name: "{{ item }}"
    state: present
  loop:
    - alice
    - bob
```



##### loop_control

`loop_control`: 用于修改 `loop` 关键字行为的一组控制选项。例如，可以使用 `loop_var` 来改变默认的 `item` 变量名，或者使用 `pause` 在每次循环之间增加一个延时。

```
- name: Create users with a custom loop variable
  ansible.builtin.user:
    name: "{{ user_name }}"
    state: present
  loop:
    - alice
    - bob
  loop_control:
    loop_var: user_name
```



##### register

`register`: 将任务的执行结果（包括标准输出、标准错误、返回码以及模块特定的返回值）捕获并存储到一个指定的变量中。这个变量可以在后续的任务中被引用，通常与 `when` 结合使用。

```
- name: Get the status of the httpd service
  ansible.builtin.command: systemctl status httpd
  register: httpd_status
  ignore_errors: true # 即使命令失败也继续执行
```



##### ignore_errors

`ignore_errors`: 一个布尔值，当设置为 `true` 时，即使当前任务执行失败，Ansible 也不会中止整个 Play 的执行，而是会继续执行后续任务。

```
- name: Run a command that might fail
  ansible.builtin.command: /path/to/some/script.sh
  ignore_errors: true
```



##### failed_when

`failed_when`: 定义一个自定义的条件表达式，用于判断任务是否失败。默认情况下，任务失败取决于模块的返回码，但通过 `failed_when`，您可以根据任务的输出内容或其他条件来精确控制失败的判定逻辑。

```
- name: Check website content
  ansible.builtin.uri:
    url: http://example.com
    return_content: yes
  register: webpage
  failed_when: "'Welcome' not in webpage.content"
```



##### changed_when

`changed_when`: 定义一个自定义的条件表达式，用于判断任务是否对系统状态做出了更改。默认情况下，由模块自身决定其是否为 "changed" 状态，但 `changed_when` 允许您覆盖这个判定，精确控制任务的 `changed` 状态，进而影响 `notify` 是否触发。

```
- name: Run a script and check for changes
  ansible.builtin.command: /path/to/update.sh
  register: script_output
  changed_when: "'UPDATED' in script_output.stdout"
```



##### notify

`notify`: 指定一个或多个 `handler` 的名称。当且仅当当前任务的状态为 "changed" 时，它才会通知指定的 `handler` 在当前 Play 的所有 `tasks` 执行完毕后运行。

```
- name: Update the httpd configuration
  ansible.builtin.template:
    src: httpd.conf.j2
    dest: /etc/httpd/conf/httpd.conf
  notify: Restart httpd
```



##### delegate_to

`delegate_to`: 将当前任务的执行委托给另一台主机。尽管任务定义在针对 `hosts` 的 Play 中，但使用 `delegate_to` 可以让这个任务实际在另一台机器上运行，例如在一台负载均衡器上操作，而 `hosts` 指向的是后端的 web 服务器。

```
- name: Remove a backend server from the load balancer
  community.general.haproxy:
    state: disabled
    host: "{{ inventory_hostname }}"
  delegate_to: load_balancer.example.com
```



##### run_once

`run_once`: 一个布尔值，当设置为 `true` 时，该任务在一个 Play 的执行中只会在 `hosts` 列表中的第一台主机上运行一次，而不是在所有主机上都运行。

```
- name: Initialize the database schema
  ansible.builtin.command: /opt/scripts/init_db.sh
  run_once: true
```



##### async

`async`: 指定一个任务以异步方式运行。Ansible 会启动这个任务，然后不等它完成就立即开始执行下一个任务。这对于需要很长时间才能完成的操作（如系统更新或大型文件复制）非常有用。

```
- name: Run a long-running software update
  ansible.builtin.yum:
    name: '*'
    state: latest
  async: 1800 # 异步执行，超时时间为 30 分钟
  poll: 0     # 不轮询结果，直接继续
```



##### poll

`poll`: 与 `async` 配合使用，定义 Ansible 轮询异步任务执行结果的频率（秒）。如果设置为 `0`，Ansible 会立即继续执行后续任务，完全不等待或检查异步任务的结果。

```
- name: Check on the status of the long-running job
  ansible.builtin.async_status:
    jid: "{{ update_job.ansible_job_id }}"
  register: job_result
  until: job_result.finished
  retries: 30
  delay: 60
```



##### retries, until, delay

`retries`, `until`, `delay`: 这三个指令通常一起使用，用于定义任务的重试逻辑。任务会持续运行，直到 `until` 中定义的条件表达式为 `true` 或者达到 `retries` 定义的最大重试次数。每次重试之间会等待 `delay` 定义的秒数。

```
- name: Wait for a web service to come up
  ansible.builtin.uri:
    url: http://localhost:8080
  register: result
  until: result.status == 200
  retries: 5
  delay: 10
```



##### vars

`vars`: 在任务级别定义变量。这里定义的变量仅对当前任务生效，其优先级高于在 Play 或 `group_vars` 中定义的同名变量。

```
- name: Install a specific version of a package
  ansible.builtin.yum:
    name: "{{ package_name }}-{{ package_version }}"
    state: present
  vars:
    package_name: httpd
    package_version: "2.4.6"
```



##### environment

`environment`: 为当前任务的执行设置环境变量。这对于需要特定环境变量（如 `HTTP_PROXY`）才能正常运行的命令或脚本非常有用。

```
- name: Run a command with a specific proxy
  ansible.builtin.command: curl http://example.com
  environment:
    http_proxy: http://proxy.example.com:8080
```



##### no_log

`no_log`: 一个布尔值，当设置为 `true` 时，Ansible 在其日志和标准输出中会隐藏该任务的详细信息，包括传递的参数和返回值。这对于处理密码或其他敏感信息的任务至关重要。

```
- name: Set a sensitive password
  ansible.builtin.user:
    name: myuser
    password: "{{ my_secret_password | password_hash('sha512') }}"
  no_log: true
```



##### tags

`tags`: 为任务应用一个或多个标签。通过在命令行中使用 `--tags` 或 `--skip-tags`，可以精确地控制只运行或跳过带有特定标签的任务。

```
- name: Configure firewall rules
  ansible.posix.firewalld:
    service: http
    permanent: true
    state: enabled
  tags:
    - networking
    - security
```





#### Handler

Handler 本质上也是一个任务，但它具有特殊的触发机制。它**只有在被 `notify` 指令调用时才会被执行**，并且所有被触发的 Handler 会在当前 Play 的所有 `tasks` 都执行完毕后，再集中执行一次。

这非常适合用于“配置变更后重启服务”之类的场景，可以避免每次配置文件更改都重启一次服务，而是在所有配置都完成后统一重启。









**运行 Playbook**

使用 `ansible-playbook` 命令来运行您的 Playbook。

```
ansible-playbook playbook.yml -f 10
```

*运行时加上 `--verbose` 标志，可以查看成功及失败任务的详细输出。*



**在检查模式下运行 Playbook**

Ansible 的**检查模式 (check mode)** 允许您在不实际更改系统任何配置的情况下执行 Playbook。您可以使用此模式在生产环境实施前测试 Playbook，避免对系统造成意外更改的风险。



要以检查模式运行 Playbook，请向 `ansible-playbook` 命令传递 `-C` 或 `--check` 标志：

```
ansible-playbook --check playbook.yaml
```



执行此命令后，Playbook 会正常运行，但 Ansible 不会实施任何修改，而是生成一份报告，说明它**原本会做出哪些更改**。报告内容包括文件修改、命令执行和模块调用等细节。



**Ansible-Pull**

您可以颠覆传统的 Ansible 推送模式，让受管节点主动从一个中心位置拉取配置。

`ansible-pull` 是一个小脚本，它会从 Git 仓库中检出 (check out) 一份配置指令，然后运行 `ansible-playbook` 来应用这些内容。

如果您对检出的位置进行负载均衡，`ansible-pull` 的扩展能力将是无限的。

运行 `ansible-pull --help` 获取更多详细信息。



**验证 Playbook**

在运行 Playbook 之前，您可能希望对其进行验证，以捕捉语法错误和其他潜在问题。`ansible-playbook` 命令提供了多个验证选项，包括 `--check`、`--diff`、`--list-hosts`、`--list-tasks` 和 `--syntax-check`。**验证 Playbook 的工具**主题介绍了其他用于验证和测试 Playbook 的工具。



**ansible-lint**

您可以使用 `ansible-lint` 在执行 Playbook 前获得详尽且针对 Ansible 的反馈。例如，若对本页顶部的 `verify-apache.yml` Playbook 运行 `ansible-lint`，您应会得到如下结果：

```
$ ansible-lint verify-apache.yml
[403] Package installs should not use latest
verify-apache.yml:8
Task/Handler: ensure apache is at the latest version
```

***ansible-lint 默认规则页**对每种错误都有详细描述。*



## Module Call





## 变量 vars

Ansible 运用变量来管理不同系统间的差异。借助 Ansible，您仅需一条命令便可在多个系统上执行任务和 Playbook。为了体现这些不同系统间的差异，您可以使用标准的 YAML 语法（包括列表和字典）来创建变量。这些变量可以定义在 Playbook 中、清单 (inventory) 文件里、可复用的文件或角色 (roles) 中，也可以在命令行中指定。此外，您还可以在 Playbook 运行期间，通过将任务的返回值注册 (register) 为一个新变量的方式来动态创建变量。

变量一经创建，便可用于模块的参数、`when` 条件判断语句、模板以及循环之中。

在您理解了本页的概念与示例之后，**建议继续阅读关于 Ansible facts 的内容**。Facts 是 Ansible 从远程系统上采集到的特殊变量。



### 简单变量

**创建有效的变量名**

并非所有字符串都能作为有效的 Ansible 变量名。**变量名只能包含字母、数字和下划线**。Python 的关键字或 Playbook 的关键字均不能用作变量名。此外，**变量名不能以数字开头**。

变量名可以以下划线开头。在许多编程语言中，以下划线开头的变量被视为私有变量。然而，在 Ansible 中并非如此。Ansible 对待以下划线开头的变量与对待其他任何变量别无二致。因此，请勿依赖此约定来实现隐私或安全控制。

Ansible 内部定义了一些特定变量，您不能自定义这些变量。

请避免使用会覆盖 Jinja2 全局函数的变量名，这些函数已在“Playbook 指南”中列出，例如 `lookup`、`query`、`q`、`now` 和 `undef`。



**简单变量**

简单变量由一个变量名和一个单一的值构成。您可以在多个地方使用此语法以及下文将介绍的列表和字典语法。关于在**清单、Playbook、可复用文件、角色或命令行**中**设置变量**的详细信息，请参阅“变量的定义位置”。



**定义简单变量**

您可以使用标准的 YAML 语法来定义一个简单变量。例如：

```yaml
remote_install_path: /opt/my_app_config
```



**引用简单变量**

定义变量后，您可以使用 Jinja2 语法来引用它。Jinja2 变量使用**双花括号** `{{ }}`。例如，表达式 `My amp goes to {{ max_amp_value }}` 展示了最基本的变量替换形式。您可以在 Playbook 中使用 Jinja2 语法。下例展示了一个变量，它定义了一个文件的位置，该位置可能因系统而异：

```
- ansible.builtin.template:
    src: foo.cfg.j2
    dest: '{{ remote_install_path }}/foo.cfg'
```

*Ansible 允许在模板中使用 Jinja2 的循环和条件判断，但在 Playbook 中则不允许。您不能创建任务的循环。Ansible Playbook 是纯粹的、可被机器解析的 YAML。*



**何时为变量添加引号（YAML 语法注意事项）**

若一个值的开头是 `{{ foo }}`，您**必须为整个表达式加上引号**，以构成合法的 YAML 语法。否则，YAML 解析器将无法解读该语法，因为它无法判断这是一个变量还是一个 YAML 字典的开始。

```
- hosts: app_servers
  vars:
    app_path: "{{ base_path }}/22"
```



### 列表变量

**列表变量**

列表变量将一个变量名与多个值相结合。您可以将这些值存储为一个项目列表，或者用方括号 `[]` 括起来并以逗号分隔。



**将变量定义为列表**

您可以使用 YAML 列表来定义具有多个值的变量。例如：

```
region:
  - northeast
  - southeast
  - midwest
```



**引用列表变量**

若使用定义为列表（亦称数组）的变量，您可以访问列表中的特定项目。列表的第一个项目索引为 0，第二个为 1，依此类推。例如：

```
region: "{{ region[0] }}"
```



### 字典变量

**字典变量**

字典以键值对的形式存储数据。通常，您会用字典来存储相关联的数据，例如一个 ID 或用户配置文件的信息。



**将变量定义为键值对字典**

您可以使用 YAML 字典来定义更为复杂的变量。YAML 字典将键（key）映射到值（value）。例如：

```
foo:
  field1: one
  field2: two
```



**引用键值对字典变量**

若使用定义为键值对字典（亦称哈希）的变量，您可以使用**方括号表示法**或**点表示法**来访问字典中的特定项目：

```
foo['field1']
foo.field1
```

这两种方式引用的都是同一个值 (`one`)。方括号表示法总是有效。点表示法有时会引发问题，因为某些键名可能与 Python 字典的属性或方法冲突。若键名以双下划线开头和结尾（在 Python 中有特殊含义），或是任何已知的公共属性，请务必使用方括号表示法。



### 合并变量

**合并变量**

若要合并包含列表或字典的变量，您可以采用以下方法。



**合并列表变量**

您可以使用 `set_fact` 模块将多个列表合并为一个新的 `merged_list` 变量，示例如下：

```yaml
vars:
  list1:
    - apple
    - banana
    - fig
  list2:
    - peach
    - plum
    - pear
tasks:
  - name: Combine list1 and list2 into a merged_list var
    ansible.builtin.set_fact:
      merged_list: "{{ list1 + list2 }}"
```



**合并字典变量**

若要合并字典，请使用 `combine` 过滤器。例如：

```yaml
vars:
  dict1:
    name: Leeroy Jenkins
    age: 25
    occupation: Astronaut
  dict2:
    location: Galway
    country: Ireland
    postcode: H71 1234
tasks:
  - name: Combine dict1 and dict2 into a merged_dict var
    ansible.builtin.set_fact:
      merged_dict: "{{ dict1 | ansible.builtin.combine(dict2) }}"
```

*更多详情，请参阅 `ansible.builtin.combine` 文档。*



**使用 merge_variables 查找**

若要合并匹配给定前缀、后缀或正则表达式的变量，您可以使用 `community.general.merge_variables` 查找插件。例如：

```yaml
merged_variable: "{{ lookup('community.general.merge_variables', '__my_pattern', pattern_type='suffix') }}"
```



### 注册变量

您可以使用任务关键字 `register` 从一个 Ansible 任务的输出中创建一个变量。您可以在该 Play 后续的任何任务中使用这个已注册的变量。例如：

```yaml
- hosts: web_servers
  tasks:
    - name: Run a shell command and register its output as a variable
      ansible.builtin.shell: /usr/bin/foo
      register: foo_result
      ignore_errors: true

    - name: Run a shell command using output of the previous task
      ansible.builtin.shell: /usr/bin/bar
      when: foo_result.rc == 5
```

已注册的变量可以是简单变量、列表变量、字典变量或复杂的嵌套数据结构。每个模块的文档都包含一个 `RETURN` 部分，描述了该模块的返回值。要查看特定任务的返回值，请使用 `-v` 选项运行您的 Playbook。

已注册的变量**存储在内存中**，无法被缓存以供未来的 Playbook 运行使用。一个已注册的变量仅在当前 Playbook 运行的剩余时间内对该主机有效，包括同一 Playbook 运行中的后续 Play。

已注册的变量是**主机级别**的。当您在一个带有循环的任务中注册变量时，该变量将包含循环中每个项目的值。在循环期间，存入变量的数据结构会包含一个 `results` 属性，它是一个包含模块所有响应的列表。

如果一个任务失败或被跳过，Ansible 仍会注册一个带有失败或跳过状态的变量，除非该任务是因标签而被跳过。



### 引用嵌套变量

许多已注册的变量和 facts 都是嵌套的 YAML 或 JSON 数据结构。您无法使用简单的 `{{ foo }}` 语法来访问这些嵌套数据结构中的值，必须使用**方括号表示法**或**点表示法**。例如，使用方括号表示法引用 facts 中的 IP 地址：

```jinja
'{{ ansible_facts["eth0"]["ipv4"]["address"] }}'
```

使用点表示法引用 facts 中的 IP 地址：

```jinja
{{ ansible_facts.eth0.ipv4.address }}
```



**使用 Jinja2 过滤器转换变量**

Jinja2 过滤器允许您在模板表达式中转换变量的值。例如，`capitalize` 过滤器会将传递给它的任何值首字母大写；`to_yaml` 和 `to_json` 过滤器则会改变变量值的格式。Jinja2 内置了许多过滤器，Ansible 也额外提供了更多。要查找更多过滤器的示例，请参阅“使用过滤器处理数据”。



### 定义变量

**变量的定义位置**

您可以在多个地方定义变量，例如在清单、Playbook、可复用文件、角色中，以及在命令行中。Ansible 会加载它能找到的所有可能的变量，然后根据**变量优先级规则**来决定应用哪个变量。



**在清单中定义变量**

您可以为每个主机单独定义不同的变量，或为清单中的一组主机设置共享变量。例如，如果 `[boston]` 组中的所有机器都使用 `boston.ntp.example.com` 作为 NTP 服务器，您可以设置一个组变量。



**在 Play 中定义变量**

您可以直接在 Playbook 的 Play 中定义变量：

```yaml
- hosts: webservers
  vars:
    http_port: 80
```

*在 Play 中定义的变量仅对该 Play 中执行的任务可见。*



**在被包含的文件和角色中定义变量**

您可以在可复用的变量文件或角色中定义变量。若将变量定义在可复用的变量文件中，敏感变量便与 Playbook 分离。这种分离使您能够将 Playbook 存储在源代码控制软件中，甚至共享 Playbook，而无须担心暴露密码或其他敏感个人数据。

下例展示了如何包含在外部文件中定义的变量：

```yaml
- hosts: all
  remote_user: root
  vars:
    favcolor: blue
  vars_files:
    - /vars/external_vars.yml
  tasks:
    - name: This is just a placeholder
      ansible.builtin.command: /bin/echo foo
```

每个变量文件的内容都是一个简单的 YAML 字典。例如：

```yaml
---
# 在上例中，此文件路径为 vars/external_vars.yml
somevar: somevalue
password: magic
```



**在运行时定义变量**

您可以在运行 Playbook 时，通过 `--extra-vars`（或 `-e`）参数在命令行上传递变量来定义它们。

如果您在命令行上传递变量，请使用一个包含一个或多个变量的单引号字符串，格式如下。



**键值对格式**

使用 `key=value` 语法传递的值被解释为**字符串**。如果您需要传递非字符串值，如布尔值、整数、浮点数或列表，请使用 JSON 格式。

```
ansible-playbook release.yml --extra-vars "version=1.23.45 other_variable=foo"
```



**JSON 字符串格式**

```
ansible-playbook release.yml --extra-vars '{"version":"1.23.45","other_variable":"foo"}'
ansible-playbook arcade.yml --extra-vars '{"pacman":"mrs","ghosts":["inky","pinky","clyde","sue"]}'
```



**从 JSON 或 YAML 文件中加载变量**

如果您有大量特殊字符，可以使用一个包含变量定义的 JSON 或 YAML 文件。在 JSON 和 YAML 文件名前加上 `@` 符号。

```
ansible-playbook release.yml --extra-vars "@some_file.json"
ansible-playbook release.yml --extra-vars "@some_file.yaml"
```



### 优先级

**变量优先级：我应将变量置于何处？**

您可以在许多不同的地方设置多个同名变量。Ansible 会加载它能找到的所有变量，然后根据**变量优先级**来决定应用哪一个。换言之，不同的变量会按特定顺序相互覆盖。

通常，就定义变量的准则（即在何处定义何种类型的变量）达成共识的团队和项目，可以避免因变量优先级而引发的困扰。**您应当只在一个地方定义每个变量**。确定变量的定义位置，并保持简洁。



**理解变量优先级**

Ansible 确实会应用变量优先级，您或许能善加利用。以下是**从最低到最高**的优先级顺序（最后列出的变量将覆盖所有其他变量）：

1. 角色默认值 (`role defaults`)
2. 清单文件或脚本中的 `group_vars`
3. 清单目录中的 `group_vars/all`
4. Playbook 目录中的 `group_vars/all`
5. 清单目录中的 `group_vars/*`
6. Playbook 目录中的 `group_vars/*`
7. 清单文件或脚本中的 `host_vars`
8. 清单目录中的 `host_vars/*`
9. Playbook 目录中的 `host_vars/*`
10. 主机 facts 和缓存的 `set_facts`
11. Play 中的 `vars`
12. Play 中的 `vars_prompt`
13. Play 中的 `vars_files`
14. 角色中的 `vars`
15. 块中的 `vars` (仅对块内任务有效)
16. 任务中的 `vars` (仅对该任务有效)
17. `include_vars`
18. `set_facts` 和已注册的变量 (`registered vars`)
19. 角色参数 (传递给 `role` 或 `include_role` 的参数)
20. `include` 参数
21. 额外变量 (`--extra-vars` 或 `-e`) (**始终具有最高优先级**)

总的来说，Ansible 赋予那些定义时间更近、更具主动性、作用域更明确的变量更高的优先级。



**变量的作用域**

您可以根据希望值具有的作用域来决定在何处设置变量。Ansible 主要有三个作用域：

- **全局 (Global)**：通过配置文件、环境变量和命令行设置。
- **Play (Play)**：每个 Play 及其包含的结构，`vars` 条目（`vars`; `vars_files`; `vars_prompt`），角色的默认值和 `vars`。
- **主机 (Host)**：直接与主机关联的变量，如清单变量、`include_vars`、facts 或已注册的任务输出。

在模板中，您可以自动访问主机作用域内的所有变量，以及任何已注册的变量、facts 和魔法变量。



**关于设置变量位置的建议**

您应根据希望对值拥有的控制程度来选择定义变量的位置。

- **在清单中设置**与地理位置或行为相关的变量。
- **在 `group_vars/all` 文件中设置**通用的默认值。
- **在 `group_vars/my_location` 文件中设置**特定于位置的变量。
- **在角色 (`roles/x/defaults/main.yml`) 中设置默认值**，以避免“未定义变量”的错误。
- **在角色 (`roles/x/vars/main.yml`) 中设置变量**，以确保该值在该角色中使用且不被清单变量覆盖。
- **在调用角色时以参数形式传递变量**，以获得最大的清晰度、灵活性和可见性。
- **使用 `--extra-vars` (`-e`)** 来覆盖所有其他变量，当您不确定其他变量的定义情况但需要一个特定值时。

我们鼓励您在决定何处设置变量时，更多地考虑您希望覆盖该变量的难易程度或频率，而不是过度担忧变量优先级。



**使用高级变量语法**

关于用于声明变量并对 Ansible 使用的 YAML 文件中的数据进行更精细控制的高级 YAML 语法信息，请参阅“高级 Playbook 语法”。



## when 条件判断

在 Playbook 中，您可能希望根据某个 fact（关于远程系统的数据）、一个变量或前一个任务的结果来执行不同的任务或实现不同的目标。您或许希望某些变量的值依赖于其他变量的值，或者希望根据主机是否满足特定条件来创建额外的主机组。所有这些都可以通过条件判断来实现。

Ansible 在条件判断中使用 Jinja2 的测试（tests）和过滤器（filters）。Ansible 不仅支持所有标准的测试和过滤器，还增加了一些独有的。



**使用 when 的基本条件判断**

最简单的条件语句应用于单个任务。创建任务后，添加一个应用了测试的 `when` 语句即可。`when` 子句是一个不带双花括号（`{{ }}`）的原始 Jinja2 表达式。

当您运行任务或 Playbook 时，Ansible 会对所有主机评估该测试。在任何测试通过（即返回值为 `True`）的主机上，Ansible 就会运行该任务。例如，若您要在多台机器上安装 MySQL，而其中一些启用了 SELinux，您可能需要一个任务来配置 SELinux 以允许 MySQL 运行。您只希望这个任务在启用了 SELinux 的机器上执行：

```yaml
tasks:
  - name: Configure SELinux to start mysql on any port
    ansible.posix.seboolean:
      name: mysql_connect_any
      state: true
      persistent: true
    # 所有变量都可以在条件判断中直接使用，无需双花括号
    when: ansible_selinux.status == "enabled"
```



**基于 ansible_facts 的条件判断**

通常，您会希望根据 Facts 来执行或跳过某个任务。Facts 是单个主机的属性，包括 IP 地址、操作系统、文件系统状态等。利用基于 Facts 的条件判断，您可以：

- 仅当操作系统是特定版本时才安装某个软件包。
- 在具有内部 IP 地址的主机上跳过防火墙配置。
- 仅当文件系统即将满时才执行清理任务。

请参阅“常用的 Facts”部分，了解常用于条件语句的 Facts 列表。并非所有 Facts 都存在于所有主机上。例如，下例中使用的 `lsb_major_release` Fact 仅在目标主机上安装了 `lsb_release` 软件包时才存在。要查看您系统上有哪些可用的 Facts，可以在 Playbook 中添加一个 `debug` 任务：

```yaml
- name: Show facts available on the system
  ansible.builtin.debug:
    var: ansible_facts
```



以下是一个基于 Fact 的条件判断示例：

```yaml
tasks:
  - name: Shut down Debian flavored systems
    ansible.builtin.command: /sbin/shutdown -t now
    when: ansible_facts['os_family'] == "Debian"
```



如果您有多个条件，可以用括号将它们组合起来：

```yaml
tasks:
  - name: Shut down CentOS 6 and Debian 7 systems
    ansible.builtin.command: /sbin/shutdown -t now
    when: (ansible_facts['distribution'] == "CentOS" and ansible_facts['distribution_major_version'] == "6") or
          (ansible_facts['distribution'] == "Debian" and ansible_facts['distribution_major_version'] == "7")
```



您可以使用逻辑运算符来组合条件。当您有多个必须同时为真（即逻辑与 `and`）的条件时，可以将它们写成一个列表：

```yaml
tasks:
  - name: Shut down CentOS 6 systems
    ansible.builtin.command: /sbin/shutdown -t now
    when:
      - ansible_facts['distribution'] == "CentOS"
      - ansible_facts['distribution_major_version'] == "6"
```



如果一个 Fact 或变量是字符串，而您需要对其进行数学比较，请使用过滤器以确保 Ansible 将其值作为整数读取：

```yaml
tasks:
  - ansible.builtin.shell: echo "only on Red Hat 6, derivatives, and later"
    when: ansible_facts['os_family'] == "RedHat" and ansible_facts['lsb']['major_release'] | int >= 6
```



您可以将 Ansible Facts 存储为变量，用于条件逻辑，如下例所示：

```yaml
tasks:
    - name: Get the CPU temperature
      set_fact:
        temperature: "{{ ansible_facts['cpu_temperature'] }}"
    - name: Restart the system if the temperature is too high
      when: temperature | float > 90
      shell: "reboot"
```





**基于注册变量的条件判断**

在 Playbook 中，您常常希望根据前一个任务的结果来执行或跳过一个任务。例如，您可能希望在一个服务由前一个任务升级后，再对其进行配置。要创建一个基于注册变量的条件判断：

1. 使用 `register` 关键字将前一个任务的结果注册为一个变量。
2. 基于该注册变量创建一个条件测试。

注册变量的名称由 `register` 关键字创建。注册变量始终包含创建它的任务的状态以及该任务生成的任何输出。您可以在模板、`action` 行以及 `when` 条件语句中使用注册变量。您可以使用 `variable.stdout` 来访问注册变量的字符串内容。例如：

```yaml
- name: Test play
  hosts: all
  tasks:
      - name: Register a variable
        ansible.builtin.shell: cat /etc/motd
        register: motd_contents

      - name: Use the variable in conditional statement
        ansible.builtin.shell: echo "motd contains the word hi"
        when: motd_contents.stdout.find('hi') != -1
```



如果注册变量是一个列表，您可以在任务的循环中使用它。如果变量不是列表，您可以使用 `stdout_lines` 或 `variable.stdout.split()` 将其转换为列表。您还可以按其他字段分割行：

```yaml
- name: Registered variable usage as a loop list
  hosts: all
  tasks:
    - name: Retrieve the list of home directories
      ansible.builtin.command: ls /home
      register: home_dirs

    - name: Add home dirs to the backup spooler
      ansible.builtin.file:
        path: /mnt/bkspool/{{ item }}
        src: /home/{{ item }}
        state: link
      # 与 loop: "{{ home_dirs.stdout.split() }}" 效果相同
      loop: "{{ home_dirs.stdout_lines }}"
```



注册变量的字符串内容可能为空。如果您希望仅在注册变量的 `stdout` 为空的主机上运行另一个任务，可以检查其字符串内容是否为空：

```yaml
- name: check registered variable for emptiness
  hosts: all
  tasks:
      - name: List contents of directory
        ansible.builtin.command: ls mydir
        register: contents

      - name: Check contents for emptiness
        ansible.builtin.debug:
          msg: "Directory is empty"
        when: contents.stdout == ""
```



Ansible 始终会为每个主机在注册变量中记录信息，即使任务失败或因条件不满足而被跳过。要在这些主机上运行后续任务，应查询注册变量的 `is skipped` 状态（而不是查询“undefined”或“default”）。以下是基于任务成功或失败的条件判断示例。请记住，如果您希望 Ansible 在发生故障时继续在主机上执行，需要忽略错误：

```yaml
tasks:
  - name: Register a variable, ignore errors and continue
    ansible.builtin.command: /bin/false
    register: result
    ignore_errors: true

  - name: Run only if the task that registered the "result" variable fails
    ansible.builtin.command: /bin/something
    when: result is failed

  - name: Run only if the task that registered the "result" variable succeeds
    ansible.builtin.command: /bin/something_else
    when: result is succeeded

  - name: Run only if the task that registered the "result" variable is skipped
    ansible.builtin.command: /bin/still/something_else
    when: result is skipped
  
  - name: Run only if the task that registered the "result" variable changed something.
    ansible.builtin.command: /bin/still/something_else
    when: result is changed
```

**注意**：旧版本的 Ansible 使用 `success` 和 `fail`，但 `succeeded` 和 `failed` 使用了更正确的时态。现在所有这些选项都是有效的。



**基于变量的条件判断**

您还可以基于 Playbook 或清单（inventory）中定义的变量创建条件判断。由于条件判断需要布尔值输入（测试必须评估为 `True` 才能触发条件），您必须对非布尔变量应用 `| bool` 过滤器，例如内容为 ‘yes’、‘on’、‘1’ 或 ‘true’ 的字符串变量。您可以这样定义变量：

```
vars:
  epic: true
  monumental: "yes"
```



使用上述变量，Ansible 将运行其中一个任务并跳过另一个：

```
tasks:
    - name: Run the command if "epic" or "monumental" is true
      ansible.builtin.shell: echo "This certainly is epic!"
      when: epic or monumental | bool

    - name: Run the command if "epic" is false
      ansible.builtin.shell: echo "This certainly isn't epic!"
      when: not epic
```



如果某个必需的变量未被设置，您可以使用 Jinja2 的 `defined` 测试来跳过或失败。例如：

```
tasks:
    - name: Run the command if "foo" is defined
      ansible.builtin.shell: echo "I've got '{{ foo }}' and am not afraid to use it!"
      when: foo is defined

    - name: Fail if "bar" is undefined
      ansible.builtin.fail: msg="Bailing out. This play requires 'bar'"
      when: bar is undefined
```



这在与条件性导入变量文件（见下文）结合使用时特别有用。

如示例所示，您在条件判断中使用变量时无需 `{{ }}`，因为这是默认隐含的。





**在循环中使用条件判断**

当您将 `when` 语句与 `loop` 结合使用时，Ansible 会为每个条目（item）分别处理该条件。这是设计使然，以便您可以对循环中的某些条目执行任务，而跳过其他条目。例如：

```yaml
tasks:
    - name: Run with items greater than 5
      ansible.builtin.command: echo {{ item }}
      loop: [ 0, 2, 4, 6, 8, 10 ]
      when: item > 5
```



如果当循环变量未定义时需要跳过整个任务，请使用 `|default` 过滤器提供一个空迭代器。例如，当遍历一个列表时：

```yaml
- name: Skip the whole task when a loop variable is undefined
  ansible.builtin.command: echo {{ item }}
  loop: "{{ mylist|default([]) }}"
  when: item > 5
```



当遍历一个字典时，您也可以做同样的事情：

```yaml
- name: The same as above using a dict
  ansible.builtin.command: echo {{ item.key }}
  loop: "{{ query('dict', mydict|default({})) }}"
  when: item.value > 5
```



**条件判断与代码重用**

您可以将条件判断与可重用的任务文件、Playbook 或 Roles 结合使用。Ansible 对动态重用（includes）和静态重用（imports）的条件语句执行方式不同。

```yaml
# main.yml
- hosts: all
  tasks:
  - import_tasks: other_tasks.yml # 注意是 "import"
    when: x is not defined

# other_tasks.yml
- name: Set a variable
  ansible.builtin.set_fact:
    x: foo
- name: Print a variable
  ansible.builtin.debug:
    var: x
```

如果 `x` 初始未定义，`set_fact` 任务的 `when` 条件为真，任务执行后定义了 `x`。但当 Ansible 评估 `debug` 任务时，`x` 此时已被定义，因此其 `when` 条件为假，导致 `debug` 任务被跳过。如果这不是您想要的行为，请使用 `include_*`。



**条件判断与 includes**

当您对 `include_*` 语句使用条件时，该条件仅应用于 `include` 任务本身，而不应用于被包含文件中的任何任务。

```
# main.yml
- hosts: all
  tasks:
  - include_tasks: other_tasks.yml # 注意是 "include"
    when: x is not defined
```

现在，如果 `x` 初始未定义，`include` 任务的条件为真，`other_tasks.yml` 文件被包含进来。其中的 `set_fact` 和 `debug` 任务自身没有 `when` 条件，因此它们都会被执行。



**条件判断与 Roles**

您可以通过以下三种方式将条件应用于 Roles：

1. 在 `roles` 关键字下放置 `when` 语句，将相同的条件应用于 Role 中的所有任务。
2. 在 `import_role` 语句上放置 `when`，将条件应用于该静态导入 Role 中的所有任务。
3. 在 Role 内部的单个任务或块上添加条件，并结合使用动态的 `include_role`。这是唯一允许您根据 `when` 语句选择或跳过 Role 内部部分任务的方法。

例如，静态应用条件：

```yaml
- hosts: webservers
  roles:
     - role: debian_stock_config
       when: ansible_facts['os_family'] == 'Debian'
```



**基于 Facts 选择变量、文件或模板**

有时，主机的 Facts 决定了您想为某些变量使用的值，甚至是您想为该主机选择的文件或模板。例如，软件包名称在 CentOS 和 Debian 上不同。通过将变量值放在 `vars` 文件中并有条件地导入它们，您可以创建适用于多个平台和操作系统版本的 Playbook。



**基于 Facts 选择变量文件**

假设您要为 CentOS 和 Debian 服务器安装 Apache，可以创建如下变量文件：

```
# vars/RedHat.yml
---
apache: httpd
```

```
# vars/Debian.yml
---
apache: apache2
```

然后在您的 Playbook 中根据主机上收集的 Facts 导入这些变量文件：

```
- hosts: webservers
  vars_files:
    - "vars/common.yml"
    - [ "vars/{{ ansible_facts['os_family'] }}.yml", "vars/os_defaults.yml" ]
  tasks:
  - name: Make sure apache is started
    ansible.builtin.service:
      name: '{{ apache }}'
      state: started
```

Ansible 会将 `ansible_facts[‘os_family’]` 变量（例如 `RedHat` 或 `Debian`）插入文件名列表。如果 `vars/RedHat.yml` 存在，它将被加载。如果不存在，Ansible 会尝试加载备用的 `vars/os_defaults.yml`。



**基于 Facts 选择文件和模板**

当不同的操作系统风格或版本需要不同的配置文件或模板时，您可以使用相同的方法。这种方法通常比在单个模板中放入大量条件判断来覆盖多个操作系统或软件包版本要清晰得多。

```yaml
- name: Template a file
  ansible.builtin.template:
    src: "{{ item }}"
    dest: /etc/myapp/foo.conf
  loop: "{{ query('first_found', { 'files': myfiles, 'paths': mypaths}) }}"
  vars:
    myfiles:
      - "{{ ansible_facts['distribution'] }}.conf"
      -  default.conf
    mypaths: ['search_location_one/somedir/', '/opt/other_location/somedir/']
```



**调试条件判断**

如果您的 `when` 条件语句行为不符合预期，可以添加一个 `debug` 任务来确定条件是评估为 `true` 还是 `false`。条件判断中意外行为的一个常见原因是将整数作为字符串测试，或反之。要调试条件语句，请将整个语句作为 `debug` 任务的 `var` 值。

```yaml
- name: check value of return code
  ansible.builtin.debug:
    var: bar_status.rc
- name: check test for rc value as string
  ansible.builtin.debug:
    var: bar_status.rc == "127"
- name: check test for rc value as integer
  ansible.builtin.debug:
    var: bar_status.rc == 127
```

输出：

```
TASK [check value of return code] ******************
ok: [foo-1] => {
    "bar_status.rc": "127"
}
TASK [check test for rc value as string] ***********
ok: [foo-1] => {
    "bar_status.rc == \"127\"": true
}
TASK [check test for rc value as integer] **********
ok: [foo-1] => {
    "bar_status.rc == 127": false
}
```



**常用的 Facts**

以下 Ansible Facts 常用于条件判断中。



**ansible_facts[‘distribution’]**

可能的值（示例，非完整列表）： `Alpine`, `Altlinux`, `Amazon`, `Archlinux`, `ClearLinux`, `Coreos`, `CentOS`, `Debian`, `Fedora`, `Gentoo`, `Mandriva`, `OpenWrt`, `OracleLinux`, `RedHat`, `Slackware`, `SLES`, `SUSE`, `Ubuntu`, `VMwareESX`



**ansible_facts[‘distribution_major_version’]**

操作系统的主版本号。例如，对于 Ubuntu 16.04，该值为 `16`。



**ansible_facts[‘os_family’]**

可能的值（示例，非完整列表）： `AIX`, `Alpine`, `Altlinux`, `Archlinux`, `Darwin`, `Debian`, `FreeBSD`, `Gentoo`, `HP-UX`, `Mandrake`, `RedHat`, `Slackware`, `Solaris`, `Suse`, `Windows`
