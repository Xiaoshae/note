# Github Actions

GitHub Actions 是一款自动化工具，允许您在 GitHub 仓库中直接构建、测试和部署代码。它的核心思想是，当您的代码仓库中发生特定事件（比如有人提交了新代码，或者创建了新的 Pull Request）时，它能自动触发预先定义好的任务。这极大地简化了持续集成 (CI) 和持续交付 (CD) 的流程，让开发者可以更专注于编写代码。



## 概念

要理解 GitHub Actions，我们可以从三个核心概念入手，它们之间存在一个层级关系：**工作流**（Workflow） > **作业**（Job） > **步骤**（Step）/ **动作**（Action）。



**工作流（Workflow）**

**工作流**是 GitHub Actions 的最高层级，它定义了整个自动化过程。一个工作由一个或多个作业组成，流通常用于完成一个特定的任务，比如持续集成（CI）或持续部署（CD）。

一个仓库中可以有多个工作流，每个工作流都以 YAML 文件的形式存在于你仓库的 `.github/workflows/` 文件夹中，它由特定事件触发，如代码提交、拉取请求、发布版本等。。



**作业（Job）**

**作业（Job）** 是工作流中的一个独立运行单元。一个工作流可以包含多个作业，它们可以并行执行以提高效率。作业之间也可以按顺序执行，后一个作业依赖于前一个作业的结果，即设置依赖关系（例如，`job_B` 可以在 `job_A` 成功完成后才开始运行）。

每个作业都在一个独立的虚拟机，即 **Runner** 上运行，这确保了作业之间的环境是隔离且干净的。你还可以指定作业在不同的操作系统（如 Ubuntu、Windows 或 macOS）上运行。



**步骤（Step）**

步骤是作业中的最小执行单位。每个作业都由**一系列按顺序执行的步骤**组成。一个步骤可以是一个简单的 Shell 命令，也可以是调用一个 **Action**（可重用的自定义任务）的指令。

所有步骤都在同一个 Runner 上运行，如果其中任何一个步骤失败，整个作业通常会停止。为步骤命名可以帮助你在工作流日志中更轻松地追踪其执行情况。



**动作（Action）** 

**动作**是 GitHub Actions 自动化工作流的最小可复用单元。你可以把它看作是一个独立的、预先打包好的任务，比如拉取 Git 仓库代码、设置一个特定的编程环境、或者发布一个 Docker 镜像。

动作是 GitHub Actions 的核心，它让工作流变得更加模块化和高效。一个动作可以由 GitHub 社区、第三方开发者创建，也可以由你自己编写。它们通常被用来执行某个特定的、频繁重复的任务，这样你就不必在每个工作流中都重复编写相同的代码。



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

```
name: CI/CD Pipeline
```



#### run-name

run-name 字段用于为由该工作流生成的单次运行设置一个动态的名称。这个名称会显示在工作流运行列表中。你可以使用表达式和上下文变量来动态生成名称，例如引用触发事件的提交信息或拉取请求的标题。如果省略此字段，运行名称将根据触发事件自动生成。

语法示例：

```
run-name: Deploy to ${{ inputs.deploy_target }} by @${{ github.actor }}
```



#### on

on 字段是工作流配置中至关重要的部分，它定义了触发工作流运行的事件。你可以配置一个或多个事件，也可以设置定时任务。



**指定单一事件**

```
on: push
```



**多个事件：**

```
on: [push, pull_request]
```

YAML 的另一种格式（两者等价）：

```
on:
  push:
  pull_request:
```

这两种配置都表示当有 push 或 pull_request 事件发生时，工作流将被触发。



**on 的子语法详解**

这两个是最常见的事件。你可以通过过滤分支（branches）、标签（tags）或文件路径（paths）来限制工作流的触发条件。



##### branches 和 branches-ignore

**branches 和 branches-ignore**: 仅在匹配或不匹配指定分支模式时触发。

```
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

```
on:
  push:
    tags:
      - 'v1.*'
```



##### paths 和 paths-ignore

**paths 和 paths-ignore**: 仅当修改的文件路径匹配或不匹配指定模式时触发。

```
on:
  push:
    paths:
      - 'src/**'
      - 'package.json'
```



##### types

**types**: 针对 pull_request 事件，可以指定其活动类型。默认情况下，pull_request 会在 opened, synchronize, 和 reopened 这三种活动类型上触发。你可以自定义这些类型，例如：

```
on:
  pull_request:
    types: [opened, labeled, closed]
```

这表示当一个拉取请求被打开、添加标签或关闭时，工作流将被触发。



##### schedule

**schedule** 接收一个 cron 字符串数组（POSIX cron 语法），按计划定时运行工作流。

```
on:
  schedule:
    - cron: '*/15 * * * *'
```

这个例子表示每 15 分钟运行一次工作流。cron 语法的五个字段分别代表：分钟、小时、日期、月份和星期几。

注意：**GitHub Actions 的定时任务执行时间可能存在延迟**，具体取决于 GitHub 服务器的负载情况。



##### workflow_dispatch

workflow_dispatch 事件可以从 GitHub 网站的 Actions 标签页或通过 API 手动触发工作流。这对于需要手动控制的部署或测试任务非常有用。



**基础用法：**

```
on: workflow_dispatch
```



**带输入参数（inputs）**: 你可以定义输入参数，在手动触发时由用户填写。

```
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

```
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

```
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

```
env:
  SERVER_NAME: production-server
  NODE_VERSION: '18'
```

你也可以在作业层面（`jobs.<job_id>.env`）或步骤层面（`jobs.<job_id>.steps[*].env`）定义环境变量，它们的作用域会更小。



在工作流文件的 YAML 定义中，使用 env 上下文来访问你定义的环境变量。语法是：`${{ env.VARIABLE_NAME }}`。



#### defaults

**defaults** 字段用于为工作流中所有的作业设置默认值。目前，你可以为 run 步骤设置默认的 **shell** 和 **working-directory**。

可以为整个工作流中的所有 `run` 步骤设置统一的默认值，例如默认的 `shell`（如 `bash`）和 `working-directory`（工作目录）。

```
defaults:
  run:
    shell: bash
    working-directory: ./scripts
```



#### concurrency

**concurrency** 字段用于确保在同一时间只有一个使用相同并发组（concurrency group）的作业或工作流实例在运行。这对于防止同时向生产环境进行多次部署等场景非常有用。



**语法示例：**

```
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

**group**: 定义并发组的名称。可以使用表达式动态生成组名。

**cancel-in-progress**: 如果设置为 true，当一个新的工作流运行在同一个并发组中启动时，GitHub 会取消任何已经在进行中的、属于该组的运行。

这个例子使用工作流名称和分支名称来定义并发组。当对同一个分支有新的推送时，旧的、尚未完成的工作流运行将被取消[[19](https://www.google.com/url?sa=E&q=https%3A%2F%2Fvertexaisearch.cloud.google.com%2Fgrounding-api-redirect%2FAUZIYQH-Rgi14FOvN5GjEbv383el_5WivZajAjP9vT8lYnFsY26UzwdvG3zPAg7Dd8HTAf3Fe0XDBiqkt7E3qMJ53odm8kGVAn_ZbuKstXIIZ9i7ld4_bSsd3Jv3dE5tt6Hdxqxv1WlKaETNiCI4nwGtaJBWKpBV2fGl9f7efKBs2yfj-OffEw9jP9a6WMGY-411OEmIqDUgpvQgba9AhG5t3zhYTtznzmX7popeV5fqLEMomTVQ2lq2hZ4GBUeQ)]。



#### permissions

permissions 字段用于修改授予 GITHUB_TOKEN 的默认权限。GITHUB_TOKEN 是一个自动生成的密钥，用于在工作流中进行身份验证。通过 permissions，你可以遵循最小权限原则，只授予工作流完成其任务所必需的权限，从而增强安全性。



你可以为所有可用的权限范围设置 read、write 或 none。如果在顶层指定了任何一个权限，所有未明确指定的权限都会被设置为 none。

可用权限范围包括：**actions, checks, contents, deployments, id-token, issues, packages, pages, pull-requests, repository-projects, security-events, statuses** 等。



**语法示例：**

```
permissions:
  contents: read
  issues: write
```

这个配置表示，GITHUB_TOKEN 拥有读取仓库内容和写入议题（issues）的权限，而所有其他权限都被禁用。你也可以在作业层面（`jobs.<job_id>.permissions`）单独设置权限。



### 作业（Job）

`name`: 为作业定义一个可读的名称，这在工作流运行日志中非常有用，可以帮助您快速定位和理解每个作业的用途。

`runs-on`: 这是作业最关键的配置之一，用于指定作业运行的环境。您可以选择 GitHub 托管的运行器（如 `ubuntu-latest`, `windows-latest` 或 `macos-latest`），也可以使用自托管（self-hosted）的运行器，这对于需要特定环境或私有网络访问的场景非常有用。

`needs`: 允许您指定当前作业依赖于其他哪些作业。如果某个作业失败，那么依赖于它的所有作业都不会运行。这对于创建有序的、多阶段的工作流（例如：先构建，再测试，最后部署）非常重要。

`steps`: 定义了作业中要执行的所有步骤。每个步骤都是一个单独的命令或动作（action）。您可以在步骤中执行 Shell 命令，或者使用已有的 Actions 来完成特定任务，比如检出代码 (`actions/checkout@v4`) 或设置 Node.js 环境 (`actions/setup-node@v4`)。

`if`: 使用条件表达式来控制是否执行该作业。您可以根据事件类型、分支名称、提交信息或其他上下文信息来决定作业是否需要运行。例如，`if: github.event_name == 'pull_request'` 只在拉取请求时运行。

`strategy`: 用于创建构建矩阵（build matrix），这使得您可以在不同的配置组合（例如，不同的操作系统和编程语言版本）上并行运行相同的作业。这对于确保您的应用在多种环境下都能正常工作非常有用。

`concurrency`: 在作业级别控制并发性，它允许您确保特定类型的作业（例如，部署作业）在任何时候只有一个实例在运行，从而避免冲突。

`env`: 为当前作业的所有步骤定义一组环境变量。这些变量只在当前作业的上下文中可用。

`defaults`: 为当前作业的所有步骤设置默认值，例如默认的 shell。



### 步骤（Step）

`name`: 为步骤定义一个名称。这个名称会显示在工作流的日志中，方便您跟踪和调试每个步骤的执行情况。

`uses`: 这是使用预定义 **Actions** 的方式。Actions 是一段可重用的代码，由 GitHub 或社区成员编写。它们可以完成许多常见的任务，比如检出代码（`actions/checkout@v4`）、设置特定的环境（`actions/setup-node@v4`）或者发布一个包。使用 `uses` 让您无需编写复杂的脚本，就能快速集成功能。

`run`: 用于执行 Shell 命令。您可以在这里编写任何您希望在运行器上执行的命令，例如 `npm install`、`docker build` 或一个自定义脚本。

`with`: 用于向 Actions 传递参数。每个 Action 都有其特定的输入（inputs）选项，您可以使用 `with` 来配置这些选项，例如指定要检出的分支、Node.js 的版本或 API 密钥。

`env`: 允许您为当前步骤定义局部环境变量。这些变量只在该步骤的上下文中可用，并且会覆盖任何在作业或工作流级别定义的同名变量。

`if`: 使用条件表达式来控制是否执行该步骤。这在某些情况下非常有用，例如只在特定分支上运行一个部署步骤，或者只在拉取请求中运行一个代码质量检查。