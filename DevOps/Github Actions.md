# Github Actions

GitHub Actions 是一个深度集成在 GitHub 平台内的持续集成与持续交付 (CI/CD) 服务，其核心使命是自动化软件开发的构建、测试和部署流程。然而，将其仅仅视为一个传统的 CI/CD 工具会限制对其能力的理解。更准确地说，GitHub Actions 是一个事件驱动的自动化平台。它的能力远不止于处理代码的推送与合并，而是可以响应在 GitHub 仓库内发生的几乎任何活动 。例如，当有新的 issue 被创建时，可以触发一个工作流来自动添加标签；当有新成员加入项目时，可以发送欢迎信息；或者当一个版本发布成功后，可以自动通知相关的团队 。   

这种与 GitHub 生态的深度耦合是其区别于 Jenkins、GitLab CI 等其他自动化服务器的核心优势。它将自动化能力无缝地嵌入到开发者日常工作的核心平台中，使得从代码管理到部署运维的整个生命周期可以在一个统一的界面和工作流中完成。GitHub 为工作流的执行提供了由官方维护的 Linux、Windows 和 macOS 虚拟机，同时也允许用户在自己的数据中心或云基础设施中托管自有的运行器，提供了极大的灵活性 。   



## 概念

要精通 GitHub Actions，首先必须理解其架构的六个基本构建块。这六大组件相互协作，构成了一个从触发到执行的完整自动化链条。



要理解 GitHub Actions，我们可以从三个核心概念入手，它们之间存在一个层级关系：**工作流**（Workflow） > **作业**（Job） > **步骤**（Step）/ **动作**（Action）。



**工作流（Workflow）**

**工作流**是 GitHub Actions 的最高层级，它定义了整个自动化过程。一个工作由一个或多个作业组成，流通常用于完成一个特定的任务，比如持续集成（CI）或持续部署（CD）。

一个仓库中可以有多个工作流，每个工作流都以 YAML 文件的形式存在于你仓库的 `.github/workflows/` 文件夹中，它由特定事件触发，如代码提交、拉取请求、发布版本等。。



**事件 (Event)**

事件是触发工作流运行的“启动器”。它是仓库中发生的特定活动，例如代码推送 (`push`)、拉取请求 (`pull_request`) 的创建、预定的时间表 (`schedule`)，甚至可以通过 API 进行手动触发 (`workflow_dispatch`) 。



**作业（Job）**

**作业（Job）** 是工作流中的一个独立运行单元。一个工作流可以包含多个作业，它们可以并行执行以提高效率。作业之间也可以按顺序执行，后一个作业依赖于前一个作业的结果，即设置依赖关系（例如，`job_B` 可以在 `job_A` 成功完成后才开始运行）。

每个作业都在一个独立的虚拟机，即 **Runner** 上运行，这确保了作业之间的环境是隔离且干净的。你还可以指定作业在不同的操作系统（如 Ubuntu、Windows 或 macOS）上运行。



**步骤（Step）**

步骤是作业中的最小执行单位。每个作业都由**一系列按顺序执行的步骤**组成。一个步骤可以是一个简单的 Shell 命令，也可以是调用一个 **Action**（可重用的自定义任务）的指令。

所有步骤都在同一个 Runner 上运行，如果其中任何一个步骤失败，整个作业通常会停止。为步骤命名可以帮助你在工作流日志中更轻松地追踪其执行情况。



**动作（Action）** 

**动作**是 GitHub Actions 自动化工作流的最小可复用单元。你可以把它看作是一个独立的、预先打包好的任务，比如拉取 Git 仓库代码、设置一个特定的编程环境、或者发布一个 Docker 镜像。

动作是 GitHub Actions 的核心，它让工作流变得更加模块化和高效。一个动作可以由 GitHub 社区、第三方开发者创建，也可以由你自己编写。它们通常被用来执行某个特定的、频繁重复的任务，这样你就不必在每个工作流中都重复编写相同的代码。



**运行器 (Runner)**

运行器是执行工作流中作业的服务器。本质上，它是一个安装了 GitHub Actions 代理软件的虚拟机或物理机 。

GitHub 提供了官方托管的运行器，它们是临时的、干净的虚拟机，每次作业运行后都会被销毁 。同时，用户也可以在自己的基础设施上设置自托管运行器，以获得对硬件、操作系统和软件环境的完全控制。



## 变量和上下文

上下文 (Contexts) 是 GitHub 将仓库元数据、事件信息、用户配置等动态数据安全、高效地传递给隔离运行器环境的工具。

在 GitHub Actions 中，变量是传递信息和配置的基础。根据其作用域、持久性和敏感性，可以分为以下几类：



### 变量

#### 环境变量 (env)

在 GitHub Actions 工作流中，环境变量（`env`）是向脚本和命令传递动态配置的基础机制。这些变量在工作流执行期间被注入到运行器（runner）的 shell 环境中，从而允许您在不硬编码值的情况下，灵活地控制脚本行为。这种方式极大地增强了工作流的可配置性和可重用性。



环境变量的作用域遵循一个明确的层次结构，可以在三个不同级别进行定义：

- 全局工作流级别（`env:`）
- 特定的作业级别（`jobs.<job_id>.env`）
- 单个步骤级别（`jobs.<job_id>.steps[*].env`）。

当同一名称的变量在多个层级被定义时，将遵循“就近覆盖”原则。即步骤中定义的环境变量会覆盖作业和工作流级别的同名变量，而作业级别的定义则会覆盖工作流级别的，从而实现了精细化的配置控制。



在脚本中访问这些环境变量的方式取决于运行器所使用的操作系统。

Linux 和 macOS ：标准的 POSIX shell 语法 `$VAR_NAME` 来引用变量。

Windows：使用 PowerShell 的语法 `$env:VAR_NAME` 来访问。



`env` 变量最适合用于存储与执行逻辑紧密相关的非敏感配置数据。常见的应用场景包括设置编译器标志（例如 `CFLAGS: "-O2"`）、指定应用程序的运行环境（例如 `NODE_ENV: "production"`），或是定义测试覆盖率报告的输出格式。对于需要安全存储的敏感信息，如密码或 API 密钥，则应使用 GitHub Secrets。



#### 配置变量 (vars)

GitHub Actions 配置变量 (`vars`) 是一种强大的功能，专为跨多个工作流共享非敏感配置数据而设计。其核心价值在于实现配置的“一次定义，多处使用”。当您拥有需要在不同工作流、不同仓库甚至整个组织中保持一致的参数时，配置变量便成为理想的解决方案。

配置变量的管理层级分为三层：组织（Organization）、仓库（Repository）和部署环境（Environment）。这种分层结构同样遵循覆盖原则，即更具体层级的定义会优先于更宽泛层级的定义。例如，在仓库级别定义的变量会覆盖组织级别的同名变量，这使得团队可以在遵循组织统一规范的同时，根据特定项目的需求进行灵活调整。

与环境变量 (`env`) 最根本的区别在于，配置变量不会自动注入到运行器的 shell 环境中。它们被存储在一个名为 `vars` 的特定上下文中，必须在工作流文件中通过表达式语法 `${{ vars.VARIABLE_NAME }}` 进行显式引用和读取。这意味着 `vars` 主要用于控制工作流本身的逻辑和参数传递，而非直接供 shell 脚本内部使用。

一个典型的应用场景是，在组织级别定义一个 `vars.DOCKER_REGISTRY` 变量来指向公司的私有镜像仓库地址。如此一来，组织内所有项目的工作流都可以通过引用 `${{ vars.DOCKER_REGISTRY }}` 来获取该地址，无需在各自的工作流文件中重复声明。未来如果仓库地址发生变更，管理员只需在组织设置中修改一次，所有相关的工作流便会自动同步到最新的配置。



#### 默认环境变量

GitHub Actions 会为每次工作流的运行自动设置一组预定义的、只读的默认环境变量。这些变量提供了关于当前执行环境的丰富信息，是编写通用和可移植脚本的基础。由于它们是只读的，您无法在工作流中更改它们的值。

这些默认环境变量与您自定义的 `env` 变量一样，都直接注入到运行器的 shell 环境中，这使得它们可以被您的脚本和命令立即访问。例如，`GITHUB_ACTOR` 变量包含了触发工作流的用户名，`GITHUB_REPOSITORY` 提供了仓库的所有者和名称，而 `GITHUB_SHA` 则指向触发工作流的提交哈希值。此外，`GITHUB_WORKSPACE` 定义了工作目录的路径，这是代码被检出并执行操作的地方。

通过使用这些变量，您的脚本无需任何额外配置就能感知其执行上下文。例如，您可以利用 `GITHUB_SHA` 来构建一个与特定提交哈希相关联的 Docker 镜像标签，或者使用 `GITHUB_ACTOR` 在部署成功后发送通知。这种内置的便利性让您能更轻松地编写出适应不同情境的自动化脚本。



### 上下文（Contexts）

变量是用于存储单个信息的零散片段，上下文本质上是包含工作流运行各方面信息的变量集合，通过统一的表达式语法 `${{ <context> }}` 来访问。

一个至关重要的区别在于，大多数上下文及其包含的数据，在作业被分配到运行器之前，就可以被 GitHub Actions 的后端服务处理。这意味着它们能够用于**工作流顶层的逻辑控制**，例如在 `jobs.<job_id>.if` 条件中判断是否应该运行某个作业。这是默认的环境变量所无法实现的。



以下是几个最关键的上下文：



#### github

**`github` 上下文**是 GitHub Actions 中最核心、信息最丰富的上下文，它包含了当前工作流运行的所有元数据。其核心是 **`github.event` 对象**，该对象完整地携带着触发当前工作流的那个事件的 Webhook 负载（payload）。

通过 `github` 上下文，开发者可以访问触发事件的每一个细节。例如，如果一个工作流是由 **`pull_request` 事件**触发的，你可以通过 `${{ github.event.pull_request.number }}` 获取该 PR 的编号，或通过 `${{ github.event.pull_request.user.login }}` 获取创建者的用户名。



#### inputs

**`inputs` 上下文**专门用于由 **`workflow_dispatch`**（手动触发）或 **`workflow_call`**（可复用工作流）事件启动的工作流。它包含了用户在触发工作流时通过 UI 或 API 提供的所有输入参数值。

你可以通过 `${{ inputs.PARAMETER_NAME }}` 的语法来访问这些输入。这是实现工作流参数化的核心机制。例如，一个部署工作流可以接受一个名为 `environment` 的输入，然后根据其值为 `staging` 还是 `production` 来决定目标服务器和配置，从而使同一个工作流能够适应不同的部署场景。



#### secrets

**`secrets` 上下文**提供了对在组织、仓库或环境级别配置的**机密信息（Secrets）**的访问。这些机密信息在 GitHub 中以加密形式安全存储。

你可以通过 `${{ secrets.MY_SECRET }}` 的语法来访问这些值。这是在工作流中传递敏感数据（例如 API 密钥、数据库密码、私钥等）的唯一安全通道。GitHub Actions 服务会尽最大努力自动屏蔽在日志输出中引用的机密值，从而防止敏感信息意外泄露。

`secrets` 上下文与 **`vars`** 上下文的本质区别就在于其**加密存储**和**日志屏蔽机制**，这确保了敏感数据的安全性。







## 语法

### 工作流（workflow）

GitHub Actions 的工作流由一个 YAML 文件定义，该文件存放在代码仓库的 .github/workflows/ 目录下。一个工作流文件是一个可配置的自动化流程，由一个或多个作业（jobs）组成。

以下是工作流文件顶层（root-level）可用的所有语法字段（不包含 jobs）：

- **name**: 工作流的名称。
- **run-name**: 单次工作流运行的名称。
- **on**: 触发工作流执行的事件。
- **env**: 在工作流所有作业中都可用的环境变量。
- **defaults**: 工作流中所有作业的默认设置。
- **concurrency**: 控制工作流的并发执行。
- **permissions**: 授予 **GITHUB_TOKEN** 的权限。



#### name

name 字段用于指定工作流的名称。这个名称会显示在你的仓库的 "Actions" 标签页中，帮助你识别不同的工作流。这是一个可选字段，如果省略，GitHub 将会显示该工作流文件的相对路径作为其名称。

语法示例：

```yaml
name: CI/CD Pipeline
```



#### run-name

run-name 字段用于为由该工作流生成的单次运行设置一个动态的名称。这个名称会显示在工作流运行列表中。你可以使用表达式和上下文变量来动态生成名称，例如引用触发事件的提交信息或拉取请求的标题。如果省略此字段，运行名称将根据触发事件自动生成。

语法示例：

```yaml
run-name: Deploy to ${{ inputs.deploy_target }} by @${{ github.actor }}
```



#### on

on 字段是工作流配置中至关重要的部分，它定义了触发工作流运行的事件。你可以配置一个或多个事件，也可以设置定时任务。

GitHub Actions 的事件触发机制并非一个简单的 Webhook 监听器，而是一个从被动到主动、从粗放到精细的、层次分明的控制系统。基础的事件触发（如 `on: push`）是一种“被动响应”模式，它对所有匹配的事件都做出反应。而高级过滤器的引入，则赋予了开发者定义精确触发条件的权力。最终，`workflow_dispatch` 的出现，更是将触发的主动权交给了用户或外部系统。



**指定单一事件**

```yaml
on: push
```



**多个事件：**

```yaml
on: [push, pull_request]
```

YAML 的另一种格式（两者等价）：

```yaml
on:
  push:
  pull_request:
```

这两种配置都表示当有 push 或 pull_request 事件发生时，工作流将被触发。



**on 的子语法详解**

仅仅依靠事件类型来触发工作流在复杂项目中是不够的。例如，在只有一个代码仓库 (monorepo) 的项目中，修改文档不应该触发后端服务的完整构建和部署流程。为了解决这个问题，GitHub Actions 提供了一套强大的过滤机制，允许对触发条件进行精确控制 。  

你可以通过过滤分支（branches）、标签（tags）或文件路径（paths）来限制工作流的触发条件。



##### branches 和 branches-ignore

**branches 和 branches-ignore**: 仅在匹配或不匹配指定分支模式时触发。

```yaml
on:
  push:
    branches:
      - main
      - 'releases/**'
    branches-ignore:
      - 'dev/*'
```

上述示例表示，当推送到 main 分支或任何以 releases/ 开头的分支时触发，但会忽略所有以 dev/ 开头的分支。



##### tags 和 tags-ignore

**tags 和 tags-ignore**: 类似 branches，用于过滤 Git 标签。

```yaml
on:
  push:
    tags:
      - 'v1.*'
```



##### paths 和 paths-ignore

**paths 和 paths-ignore**: 仅当修改的文件路径匹配或不匹配指定模式时触发。

```yaml
on:
  push:
    paths:
      - 'src/**'
      - 'package.json'
```



##### types

**types**: 针对 pull_request 事件，可以指定其活动类型。默认情况下，pull_request 会在 opened, synchronize, 和 reopened 这三种活动类型上触发。你可以自定义这些类型，例如：

```yaml
on:
  pull_request:
    types: [opened, labeled, closed]
```

这表示当一个拉取请求被打开、添加标签或关闭时，工作流将被触发。



##### schedule

**schedule** 接收一个 cron 字符串数组（POSIX cron 语法），按计划定时运行工作流。

```yaml
on:
  schedule:
    - cron: '*/15 * * * *'
```

这个例子表示每 15 分钟运行一次工作流。cron 语法的五个字段分别代表：分钟、小时、日期、月份和星期几。

注意：**GitHub Actions 的定时任务执行时间可能存在延迟**，具体取决于 GitHub 服务器的负载情况。



##### workflow_dispatch

workflow_dispatch 事件可以从 GitHub 网站的 Actions 标签页或通过 API 手动触发工作流。这对于需要手动控制的部署或测试任务非常有用。



**基础用法：**

```yaml
on: workflow_dispatch
```



**带输入参数（inputs）**: 你可以定义输入参数，在手动触发时由用户填写。

```yaml
on:
  workflow_dispatch:
    inputs:
      logLevel:
        description: 'Log level'
        required: true
        default: 'warning'
        type: choice
        options:
        - info
        - warning
        - debug
      environment:
        description: 'Environment to run tests against'
        type: environment
        required: true
```

在这个例子中，手动触发工作流时，用户需要选择一个日志级别并指定一个环境。这些输入值可以在工作流的 jobs 中通过 inputs 上下文进行访问 (例如 ${{ inputs.logLevel }} 或 ${{ github.event.inputs.logLevel }})。





##### workflow_call

workflow_call 用于定义可重用工作流，在被调用的工作流中，on 字段必须包含 workflow_call。

```yaml
on:
  workflow_call:
    inputs:
      config-path:
        required: true
        type: string
    secrets:
      personal_access_token:
        required: true
```

这个工作流可以接收来自调用者的输入参数（inputs）和密钥（secrets）。



**调用可重用工作流**

调用工作流的 jobs 中，使用 uses 关键字来指定要调用的工作流文件路径，并用 with 传递输入，用 secrets 传递密钥。

```yaml
jobs:
  call-reusable-workflow:
    uses: octo-org/example-repo/.github/workflows/reusable-workflow.yml@main
    with:
      config-path: '.github/labeler.yml'
    secrets:
      personal_access_token: ${{ secrets.GH_TOKEN }}
```



#### env

workflow 中的 env 字段允许你在工作流的顶层定义环境变量。在这里定义的环境变量对于工作流中的所有作业（jobs）和步骤（steps）都是可用的。



基础语法：

```yaml
env:
  SERVER_NAME: production-server
  NODE_VERSION: '18'
```

你也可以在作业层面（`jobs.<job_id>.env`）或步骤层面（`jobs.<job_id>.steps[*].env`）定义环境变量，它们的作用域会更小。



在工作流文件的 YAML 定义中，使用 env 上下文来访问你定义的环境变量。语法是：`${{ env.VARIABLE_NAME }}`。



#### defaults

**defaults** 字段用于为工作流中所有的作业设置默认值。目前，你可以为 run 步骤设置默认的 **shell** 和 **working-directory**。

可以为整个工作流中的所有 `run` 步骤设置统一的默认值，例如默认的 `shell`（如 `bash`）和 `working-directory`（工作目录）。

```yaml
defaults:
  run:
    shell: bash
    working-directory: ./scripts
```



#### concurrency

**concurrency** 字段用于确保在同一时间只有一个使用相同并发组（concurrency group）的作业或工作流实例在运行。这对于防止同时向生产环境进行多次部署等场景非常有用。



**语法示例：**

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

**group**: 定义并发组的名称。可以使用表达式动态生成组名。

**cancel-in-progress**: 如果设置为 true，当一个新的工作流运行在同一个并发组中启动时，GitHub 会取消任何已经在进行中的、属于该组的运行。

这个例子使用工作流名称和分支名称来定义并发组。当对同一个分支有新的推送时，旧的、尚未完成的工作流运行将被取消。



#### permissions

permissions 字段用于修改授予 GITHUB_TOKEN 的默认权限。GITHUB_TOKEN 是一个自动生成的密钥，用于在工作流中进行身份验证。通过 permissions，你可以遵循最小权限原则，只授予工作流完成其任务所必需的权限，从而增强安全性。



你可以为所有可用的权限范围设置 read、write 或 none。如果在顶层指定了任何一个权限，所有未明确指定的权限都会被设置为 none。

可用权限范围包括：**actions, checks, contents, deployments, id-token, issues, packages, pages, pull-requests, repository-projects, security-events, statuses** 等。



**语法示例：**

```yaml
permissions:
  contents: read
  issues: write
```

这个配置表示，GITHUB_TOKEN 拥有读取仓库内容和写入议题（issues）的权限，而所有其他权限都被禁用。你也可以在作业层面（`jobs.<job_id>.permissions`）单独设置权限。



### 作业（Job）

在 GitHub Actions 工作流程（workflow）的 YAML 文件中，jobs 键的下一层**只能是具体的作业（job）定义**。

jobs 本身是一个包含了所有作业的**映射（map）**。这个映射的每一个键（key）就是一个唯一的作业 ID (`<job_id>`)，而对应的值（value）则是该作业的所有配置项（如 name, runs-on, steps 等）。



**正确的语法结构：**

```yaml
# 这是工作流的顶层
name: My Workflow
on: [push]

# "jobs" 是一个顶层键
jobs:
  # "build" 是一个 job ID，是 "jobs" 下的第一层
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building..."

  # "test" 是另一个 job ID，也是 "jobs" 下的第一层
  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: echo "Testing..."
```



#### jobs.<job_id>

每个 job 都必须有一个唯一的标识符 `<job_id>`。这个 ID 必须以字母或 _ 开头，并且只能包含**字母、数字、`-` 和 `_`**。

**语法示例：**

```
jobs:
  build:
    # ... job configuration
  test:
    # ... job configuration
```



#### name

为 job 设置一个在 GitHub UI 中显示的名称。如果省略，将显示 job 的 ID。

**语法：**

```
name: <string>
```



#### needs

指定当前 job 开始前必须成功完成的 job。它可以是一个 job ID 字符串，也可以是一个 job ID 的数组。如果依赖的 job 失败或被跳过，那么当前 job 也会被跳过，除非使用了特定的条件表达式来强制执行。



**语法：**

```
needs: <job_id> | [<job_id>, ...]
```



示例：

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building..."
  test:
    name: Run tests
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: echo "Testing..."
```

在这个例子中，test job 会在 build job 成功完成后才会开始执行。



#### runs-on

指定 job 运行的虚拟机环境。这是每个 job 的必需字段。你可以使用 GitHub 托管的运行器，也可以使用自托管的运行器。



**语法：**

```
runs-on: <runner_label>
```



**常见的 GitHub 托管运行器标签：**

- ubuntu-latest
- windows-latest
- macos-latest



**示例：**

```yaml
jobs:
  build-on-linux:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Running on Linux"
```



#### permissions

为单个 job 中 GITHUB_TOKEN 的权限进行配置。这可以覆盖工作流程级别的 permissions 设置。为 GITHUB_TOKEN 授予最低权限是保障安全性的良好实践。



**示例：**

```yaml
jobs:
  update-release:
    runs-on: ubuntu-latest
    permissions:
      contents: write # 允许 action 创建一个 release
      pull-requests: read
    steps:
      - run: echo "Updating release..."
```





#### if

一个条件表达式，用于决定 job 是否执行。job 只有在条件为 true 时才会运行。你可以使用包含任何上下文信息（如 github、inputs 等）的表达式。



**语法：**

```
if: <expression>
```



**示例：**

```
jobs:
  deploy-to-production:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - run: echo "Deploying to production..."
```

这个 job 仅在 push 事件发生在 main 分支时才会执行。



#### steps

一个 job 包含一系列按顺序执行的任务，称为步骤（steps）。每个 step 可以是一个 shell 命令（run）或者是一个预定义的操作（uses）。



**语法规则：**

```yaml
steps:
  - name: <string>
    uses: <action_name>
    with:
      <input_name>: <value>
  - name: <string>
    run: <command>
```





**示例：**

```
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository code
        uses: actions/checkout@v4

      - name: Install dependencies
        run: npm install

      - name: Run tests
        run: npm test
```



#### strategy

定义一个构建矩阵（matrix），允许你通过执行 job 的多个变体来复用其配置。例如，你可以使用不同的语言版本或操作系统来运行同一个 job。



**语法：**

```yaml
strategy:
  matrix:
    <matrix_key>: [<value1>, <value2>, ...]
  fail-fast: <boolean>
  max-parallel: <number>
```

- matrix: 定义不同配置的组合。
- fail-fast: 默认为 true。如果任何一个矩阵中的 job 失败，GitHub 将立即取消所有其他正在进行的 job。
- max-parallel: 可以同时运行的 job 的最大数量。



**示例：**

```yaml
jobs:
  test-matrix:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18, 20, 22]
        os: [ubuntu-latest, windows-latest]
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
      - run: echo "Testing on ${{ matrix.os }} with Node ${{ matrix.node-version }}"
```



#### outputs

定义一个 job 的输出。这些输出可供其他依赖于此 job 的 job 使用。

**outputs** 一般搭配 **needs** 一起使用。



**语法：**

```yaml
outputs:
  <output_name>: ${{ steps.<step_id>.outputs.<output_name> }}
```



**示例：**

```yaml
jobs:
  job1:
    runs-on: ubuntu-latest
    outputs:
      output1: ${{ steps.step1.outputs.test }}
    steps:
      - id: step1
        run: echo "test=hello" >> "$GITHUB_OUTPUT"
  job2:
    runs-on: ubuntu-latest
    needs: job1
    steps:
      - run: echo ${{ needs.job1.outputs.output1 }} # 输出 'hello'
```



#### environment

定义 job 引用的环境。配置了部署保护规则（如需要审批）的环境，在 job 尝试部署到该环境前，必须通过所有规则。



语法：

```yaml
environment: <environment_name> | <environment_object>
```



示例：

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://github.com
    steps:
      - run: echo "Deploying to production"
```



##### concurrency

确保在同一时间，只有一个使用相同并发组（concurrency group）的 job 或 workflow 能够运行。 



#### env

为 job 内的所有步骤设置环境变量。



#### defaults

为 job 内的所有步骤设置默认值。



#### timeout-minutes

设置 job 在被自动取消前可以运行的最长时间，单位为分钟。默认是 360 分钟（6小时）。



**语法：**

```yaml
timeout-minutes: <minutes>
```



**示例：**

```yaml
jobs:
  long-running-job:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: sleep 700 # 这个 job 会在 10 分钟后超时
```



#### continue-on-error

防止 job 在某一步失败时导致整个 workflow 失败。当设置为 true 时，即使此 job 失败，workflow 的执行也会继续。这对于非关键性的 job 很有用。



**语法：**

```yaml
continue-on-error: <boolean>
```



**示例：**

```yaml
jobs:
  non-critical-job:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: exit 1 # 即使这一步失败，workflow 也不会立即停止
```



#### container

指定一个 Docker 容器来**运行 job 的所有步骤**。这允许你定义一个特定的环境，包括依赖项和工具。



**语法：**

```yaml
container:
  image: <image_name>
  env:
    <variable_name>: <value>
  ports:
    - <port_mapping>
  volumes:
    - <volume_mapping>
  options: <docker_options>
```



**示例：**

```yaml
jobs:
  container-job:
    runs-on: ubuntu-latest
    container:
      image: node:18
    steps:
      - run: node --version
```



#### services

在 job 的执行过程中，启动一个或多个服务容器。这对于需要数据库或其他服务的集成测试非常有用。



**语法：**

```yaml
services:
  <service_id>:
    image: <image_name>
    env:
      <variable_name>: <value>
    ports:
      - <port_mapping>
    options: <docker_options>
```



**示例**

```yaml
jobs:
  test-with-db:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_USER: user
          POSTGRES_PASSWORD: password
          POSTGRES_DB: testdb
        ports:
          - 5432:5432
    steps:
      - run: |
          # 等待数据库启动
          # 运行连接数据库的测试
          echo "Running tests against PostgreSQL"
```





### 步骤（Step）

在 GitHub Actions 的工作流程（workflow）中，steps 是作业（job）的核心组成部分。它是一个包含了按顺序执行的一系列任务（步骤）的列表。每一个步骤都可以在运行器（runner）环境中执行命令或者使用一个预定义的操作（action）。



#### run

指定此步骤在运行器的命令行中执行的命令。可以是单行命令，也可以是多行脚本。对于多行脚本，建议使用 `|` 符号，以确保 YAML 的可读性。



**语法：**

```
run: <command>
```



**示例：**

```
steps:
  - name: Install dependencies
    run: npm install

  - name: Run build script
    run: |
      echo "Starting the build process..."
      npm run build
```

第一个步骤执行单行命令，第二个步骤执行多行脚本。



#### uses

指定此步骤要运行的操作（action）。Action 是可重用的代码单元。你可以使用 GitHub Marketplace 中的 action、仓库中的自定义 action 或 Docker Hub 上的 action。强烈建议为 action 指定一个版本号（通常是 Git ref、SHA 或 Docker 标签），以保证工作流程的稳定性。



**语法：**

```
uses: <action_name>@<version>
```



**示例：**

```yaml
steps:
  - name: Check out repository code
    uses: actions/checkout@v4
```

此步骤使用官方的 `actions/checkout` action 的 `v4` 版本来检出仓库代码。



#### id

**通用子语法，以下语法可以与 `uses` 或 `run` 配合使用，为步骤提供更多配置和控制。**



为步骤设置一个唯一的标识符。这个 ID 允许你在同一作业的其他步骤中引用此步骤的输出或结论。



**语法：**

```
id: <string>
```



**示例：**

```yaml
steps:
  - id: step_one
    run: echo "output_value=hello" >> "$GITHUB_OUTPUT"

  - id: step_two
    run: echo "The output was ${{ steps.step_one.outputs.output_value }}"
```

`step_two` 通过 `steps` 上下文引用了 `step_one` 的输出。



#### name

为步骤设置一个在 GitHub UI 中显示的名称。这有助于在查看工作流日志时清晰地了解每个步骤的作用。



**语法：**

```yaml
name: <string>
```



**示例：**

```yaml
steps:
  - name: Display current directory
    run: ls -la
```



#### if

一个条件表达式，用于决定步骤是否执行。只有当条件为 `true` 时，步骤才会运行。你可以使用任何支持的上下文和表达式来创建条件。



**语法：**

```
if: <expression>
```



示例：

```yaml
steps:
  - name: Deploy to production
    if: github.ref == 'refs/heads/main'
    run: echo "Deploying..."
```

此步骤仅在工作流程的触发事件发生在 `main` 分支时才会执行。



#### with

一个包含 action 所需输入参数的映射（map）。这些参数由 action 的作者定义。对于 Docker 类型的 action，还支持 `args` 和 `entrypoint`。



**语法：**

```yaml
with:
  <input_name>: <value>
```



**示例：**

```yaml
steps:
  - name: Setup Node.js
    uses: actions/setup-node@v4
    with:
      node-version: '20'
```

此步骤向 `actions/setup-node` 传递了 `node-version` 这个输入参数。



#### env

为该步骤设置特定的环境变量。这些变量会覆盖在作业或工作流级别定义的环境变量。



**语法：**

```
env: <map_of_variables>
```



**示例：**

```
steps:
  - name: Run a command with a specific environment variable
    env:
      NODE_ENV: test
    run: echo "The environment is $NODE_ENV"
```

此步骤中的 `NODE_ENV` 变量仅在该步骤内有效。



#### working-directory

指定 `run` 命令执行的默认工作目录。如果未设置，命令将在仓库的根目录下执行。



**语法：**

```yaml
working-directory: <directory_path>
```



**示例：**

```yaml
steps:
  - name: Run script in a subdirectory
    working-directory: ./scripts
    run: ./my-script.sh
```

`my-script.sh` 将在 `scripts` 目录中被执行。



#### shell

指定用于执行 `run` 命令的 shell。你可以选择预设的 shell，如 `bash`、`pwsh`、`python` 等，也可以提供一个自定义的 shell 模板。



**语法：**

```
shell: <shell_keyword>
```



**示例：**

```
steps:
  - name: Run a PowerShell script on Linux
    shell: pwsh
    run: Get-ChildItem -Path .
```

这个步骤将在 Linux 运行器上使用 PowerShell Core 来执行命令。



#### continue-on-error

防止单个步骤的失败导致整个作业失败。如果设置为 `true`，即使此步骤失败（返回非零退出码），作业中的后续步骤仍然会继续执行。



语法：

```
continue-on-error: <boolean>
```



**示例：**

```yaml
steps:
  - name: A step that might fail
    continue-on-error: true
    run: exit 1
  - name: This step will run even if the previous one fails
    run: echo "I am still running!"
```



#### timeout-minutes

设置步骤在被自动取消前可以运行的最长时间，单位为分钟。默认情况下，作业本身有一个超时限制（通常是 6 小时），但你可以为特定的、可能耗时较长的步骤设置更短的超时时间。



**语法：**

```
timeout-minutes: <number>
```





### Container

在 GitHub Actions 中，你可以使用 `container` 关键字在 Docker 容器中执行你的作业（job）。这对于确保你的构建或测试环境一致性非常有用。



#### image

指定要用于作业的 Docker 镜像。这是 `container` 中唯一必填的字段。你可以使用 Docker Hub 上的公共镜像，也可以使用私有镜像仓库中的镜像。



**语法：**

```
image: <docker_image>
```



**示例：**

```python
jobs:
  my_job:
    runs-on: ubuntu-latest
    container:
      image: node:16-alpine
    steps:
      - run: node --version
```

在这个例子中，`my_job` 将在一个基于 `node:16-alpine` 镜像的容器中运行。



#### credentials

如果你的 Docker 镜像位于需要身份验证的私有仓库中，你可以使用 `credentials` 来提供用户名和密码。



**语法：**

```
credentials:
  username: <username>
  password: <password>
```



**示例：**

```
jobs:
  my_job:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/my_org/my_image:latest
      credentials:
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - run: echo "Running in a private container"
```

这里使用了 `GITHUB_TOKEN` 来访问 GitHub Container Registry (GHCR) 上的私有镜像。



#### env

你可以使用 `env` 来为容器设置环境变量。这些环境变量在容器内部的所有步骤中都可用。

**语法：**

```
env:
  <name>: <value>
```



**示例：**

```
jobs:
  my_job:
    runs-on: ubuntu-latest
    container:
      image: python:3.9
      env:
        PYTHONPATH: /app
    steps:
      - run: python -c "import os; print(os.environ['PYTHONPATH'])"
```



#### ports

将容器内的端口映射到 GitHub Actions 运行器的端口，这对于需要暴露服务的应用程序（如 Web 服务器）的测试很有用。

**语法：**

```
ports:
  - <port> | <port>:<host_port>
```



**示例：**

```
jobs:
  my_job:
    runs-on: ubuntu-latest
    container:
      image: nginx:latest
      ports:
        - 8080:80
    steps:
      - run: curl http://localhost:8080
```

在这个例子中，容器内的 80 端口被映射到运行器上的 8080 端口。

注意：这个例子是 AI 生成的，认为此处的 run 执行的命令不太恰当。



#### volumes

将运行器上的路径挂载到容器内的指定路径，这使得容器可以访问运行器上的文件系统。



**语法：**

```
volumes:
  - <source_path>:<destination_path>:<permissions>
```



**示例：**

```
jobs:
  my_job:
    runs-on: ubuntu-latest
    container:
      image: alpine:latest
      volumes:
        - /tmp:/data
    steps:
      - run: echo "Hello world" > /data/test.txt
      - run: cat /tmp/test.txt
```

在这个例子中，运行器上的 `/tmp` 目录被挂载到容器内的 `/data` 目录。



#### options

用于传递额外的命令行选项给 `docker run` 命令。这允许你更精细地控制容器的行为。

**语法：**

```
options: <docker_run_options>
```



**示例：**

```
jobs:
  my_job:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:20.04
      options: --name my-container --hostname my-host -e TZ=Asia/Shanghai
    steps:
      - run: date
```

这里通过 `--name` 和 `--hostname` 设置了容器的名称和主机名，并通过 `-e` 设置了时区环境变量。



#### entrypoint

覆盖 Docker 镜像中默认的 `ENTRYPOINT`。



**语法：**

```
entrypoint: <command>
```



**示例：**

```
jobs:
  my_job:
    runs-on: ubuntu-latest
    container:
      image: alpine:latest
      entrypoint: /bin/sh
    steps:
      - run: echo "Hello from sh"
```

这个例子中，即使 `alpine` 镜像的 `ENTRYPOINT` 不是 `/bin/sh`，也会被强制覆盖。