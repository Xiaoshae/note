# PDO

PDO 是一个数据库访问抽象层。这种抽象是双重的：一个广为人知但相对不那么重要，而另一个则鲜为人知但却至关重要。

众所周知，PDO 提供了一个统一的接口来访问许多不同的数据库。尽管这一特性本身非常出色，但对于只使用一种数据库后端的特定应用来说，并没有太大的实际意义。而且，尽管有些传言称可以通过更改 PDO 配置中的一行代码来切换数据库后端，但实际上由于不同的 SQL 方言（要实现这一点，需要使用像 DQL 这样的平均化查询语言），这是不可能的。

因此，对于普通的 LAMP 开发者而言，这一点相对来说并不重要，对他们来说，PDO 只不过是 `mysql(i)_query()` 函数的一个更复杂的版本。然而，事实并非如此；PDO 的功能远不止于此。

PDO 抽象化的不仅仅是数据库 API，还包括那些在每个应用程序中都需要重复数百次的基础操作，这使得你的代码极其遵循 DRY 原则（Don't Repeat Yourself，即“不要重复自己”）。

PDO 的真正优势在于：

- **安全性**：可以使用准备好的语句（prepared statements），从而有效防止 SQL 注入攻击。
- **易用性**：提供了许多辅助函数来自动化常规操作，简化了开发工作。
- **可复用性**：提供了一个统一的 API 来访问从 SQLite 到 Oracle 的多种数据库，使得代码可以在不同数据库之间轻松移植。



## DSN

DSN 是 PDO（PHP Data Objects）用于连接数据库的一种方法。它并不复杂，只是与传统的一串简单选项不同，PDO 要求你在三个不同的地方输入不同的配置指令（以下例子以 MySQL 为例，对于其他驱动程序，请参阅 PHP 手册中相应的部分）：

1. 数据库驱动、主机、数据库（模式）名称和字符集，以及较少使用的端口和 Unix 套接字被放在 DSN 中；
2. 用户名和密码在构造函数中提供；
3. 所有其他选项放入选项数组中。



DSN 是一个分号分隔的字符串，由 param=value 对组成，并且从驱动名称和冒号开始：

```
      mysql:host=localhost;dbname=test;port=3306;charset=utf8mb4
driver^    ^ colon         ^param=value pair    ^semicolon  
```

请注意，遵循正确的格式非常重要 - DSN 中不能使用空格或引号或其他装饰，只能使用参数、值和分隔符，如手册所示。



以下是 MySQL 的示例：

```php
$host = '127.0.0.1';
$db   = 'test';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];
$pdo = new PDO($dsn, $user, $pass, $options);
```

通过正确设置所有上述变量，我们将在 `$pdo` 变量中拥有一个正确的 PDO 实例。



重要注意事项：

- 与可以在代码任何地方使用的旧版 `mysql_*` 函数不同，PDO 实例存储在一个普通变量中，这意味着它可能在函数内部不可访问 - 因此，需要通过函数参数传递它，或者使用更高级的技术，比如 IoC 容器来使其可访问。
- 必须严格只建立一次连接！不要在每个函数或类构造函数中创建连接。否则会创建多个连接，这最终会拖垮你的数据库服务器。因此，应该创建唯一的 PDO 实例并在整个脚本执行过程中使用它。
- 设置 DSN 中的字符集非常重要 - 这是唯一正确的方法，因为它告诉 PDO 将要使用的字符集。所以请忘记通过 `query()` 或 `PDO::MYSQL_ATTR_INIT_COMMAND` 手动运行 `SET NAMES` 查询。只有当你的 PHP 版本过低（即低于 5.3.6）时，才需要使用 `SET NAMES` 查询，并始终关闭模拟模式。



## 

在 PDO 中执行查询有两种方法。如果查询中不涉及变量，你可以使用 `PDO::query()` 方法。它将执行你的查询并返回一个 `PDOStatement` 类的特殊对象，这个对象可以大致类比于由 `mysql_query()` 返回的资源，尤其是在从它那里获取实际行的方式上：

```php
$stmt = $pdo->query('SELECT name FROM users');
while ($row = $stmt->fetch()) {
    echo $row['name'] . "\n";
}
```



此外，`query()` 方法允许我们对 `SELECT` 查询使用方便的方法链（method chaining），这将在下面展示。

对于不包含变量的简单查询，`PDO::query()` 是一个快捷且直接的方法。它适合用于那些不需要参数化的查询，例如获取数据表中的所有记录或统计信息。然而，当需要在 SQL 语句中插入变量时，推荐使用预处理语句来增强安全性，避免 SQL 注入攻击。

下面是使用 `PDO::query()` 执行查询并使用方法链的一个例子：

```php
// 假设我们有一个 PDO 实例 $pdo

// 使用 query() 方法执行 SELECT 查询，并链式调用 fetchAll() 获取所有结果
$rows = $pdo->query('SELECT name, email FROM users')->fetchAll(PDO::FETCH_ASSOC);

foreach ($rows as $row) {
    echo "Name: " . htmlspecialchars($row['name']) . ", Email: " . htmlspecialchars($row['email']) . "\n";
}
```

在这个例子中，`query()` 方法被用来执行一个简单的 `SELECT` 语句，并立即调用了 `fetchAll()` 方法来获取查询的所有结果，最后通过 foreach 循环遍历结果集。

请注意，尽管 `PDO::query()` 对于简单的查询非常有用，但在执行涉及用户输入或其他外部数据的查询时，应该总是使用预准备语句 (`PDO::prepare()` 和 `PDOStatement::execute()`) 来确保应用程序的安全性。



## 预处理语句

PDO内置支持预处理语句。预处理语句（也称为参数化查询）是在任何查询中使用变量时的唯一正确方法。它之所以如此重要，是因为它可以有效预防SQL注入攻击，这一点在《SQL注入预防指南》中有详细解释。

因此，对于每个你运行的查询，如果至少要使用一个变量，你就需要用占位符代替该变量，然后准备你的查询，并通过分离的方式执行它，传递变量。



在大多数情况下，你只需要两个函数 - prepare() 和 execute()。

首先，你必须修改你的查询，在变量的位置添加占位符。例如，这样的代码

```php
$sql = "SELECT * FROM users WHERE email = '$email' AND status='$status'";
```

将变为

```php
$sql = 'SELECT * FROM users WHERE email = ? AND status=?';
```

或

```php
$sql = 'SELECT * FROM users WHERE email = :email AND status=:status';
```



请注意，PDO 支持位置型（?）和命名型（:email）占位符，后者总是以冒号开头，并且只能由字母、数字和下划线组成。另外要注意的是，占位符周围永远不需要加引号。

有了带有占位符的查询后，你需要使用 PDO::prepare() 方法来准备它。这个函数会返回我们之前提到的 PDOStatement 对象，但没有任何数据附加到它上面。

最后，为了执行查询，你必须运行此对象的 execute() 方法，以数组的形式传入变量。之后，你可以从语句中获取结果数据（如果适用）：

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? AND status=?');
$stmt->execute([$email, $status]);
$user = $stmt->fetch();
// 或者
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email AND status=:status');
$stmt->execute(['email' => $email, 'status' => $status]);
$user = $stmt->fetch();
```

如你所见，对于位置型占位符，你需要提供一个普通数组，其中包含值，而对于命名型占位符，则需要一个关联数组，其键必须与查询中的占位符名称匹配。你不能在同一查询中混合使用位置型和命名型占位符。



### 绑定方法

将数据传入 `execute()`（如上所示）应被视为默认且最便捷的方法。使用此方法时，所有值都将作为字符串绑定（NULL 值除外，NULL 值将直接作为 SQL NULL 发送到查询中），但在大多数情况下这是完全可以接受的，不会造成任何问题。

不过，在某些情况下，最好显式地设置数据类型。可能的情况有：

- 如果启用了模拟模式，则对于 LIMIT 子句（或任何不能接受字符串操作数的 SQL 子句）。
- 对于复杂查询，其查询计划可能会因错误的操作数类型而受到影响。
- 对于特殊的列类型，如 BIGINT 或 BOOLEAN，这些类型要求绑定确切类型的操作数（请注意，为了使用 PDO::PARAM_INT 绑定 BIGINT 值，你需要基于 mysqlnd 的安装）。



在这种情况下，必须使用显式绑定，你可以选择两个函数之一，`bindValue()` 和 `bindParam()`。前者通常更受欢迎，因为它不像 `bindParam()` 会有副作用需要处理。



### 你可以绑定的查询部分

实际上，可以绑定的部分列表非常有限：只有字符串和数值字面量可以被绑定。也就是说，只要你的数据可以在查询中表示为数值或带引号的字符串字面量，就可以被绑定。

对于所有其他情况，你无法使用 PDO 预处理语句：无论是标识符、逗号分隔的列表、带引号的字符串字面量的一部分，还是任意其他的查询部分都不能使用预处理语句绑定。



## 一次预处理；多次执行

有时你可以使用预处理语句来多次执行一个准备好的查询。这比一次又一次地执行相同的查询略快，因为它只解析一次查询。

```php
$data = [
    1 => 1000,
    5 => 300,
    9 => 200,
];
$stmt = $pdo->prepare('UPDATE users SET bonus = bonus + ? WHERE id = ?');
foreach ($data as $id => $bonus)
{
    $stmt->execute([$bonus, $id]);
}
```



## SELECT、INSERT、UPDATE 或 DELETE 语句

INSERT、UPDATE 或 DELETE 与 SELECT 查询没有区别。

正如上面所展示的，你需要做的是用占位符准备一个查询，然后通过分离的方式执行它，发送变量。对于 DELETE 和 SELECT 查询，过程基本上是相同的。



唯一的不同在于（因为 DML 查询不返回任何数据），你可以使用方法链式调用，在 prepare() 后直接调用 execute()：

```php
$sql = "UPDATE users SET name = ? WHERE id = ?";
$pdo->prepare($sql)->execute([$name, $id]);
```



然而，如果你想获取受影响的行数，代码将不得不仍然是那三行不变的代码：

```php
$stmt = $pdo->prepare("DELETE FROM goods WHERE category = ?");
$stmt->execute([$cat]);
$deleted = $stmt->rowCount();
```



## 从语句中获取数据

从语句中获取多行数据最基础和直接的方法是 foreach() 循环。由于 PDOStatement 实现了 Traversable 接口，可以使用 foreach() 操作符对其进行迭代：

```php
$stmt = $pdo->query('SELECT name FROM users');
foreach ($stmt as $row)
{
    echo $row['name'] . "\n";
}
```

请注意，这种方法对内存友好，因为它不会将所有结果行加载到内存中，而是逐个提供（不过请记住这个问题）。



### fetch()

`fetch()` 函数从数据库中获取单行，并移动结果集中的内部指针，因此后续对该函数的调用将依次返回所有结果行。

PDO 中有许多 fetch 模式，我们稍后会讨论它们，但这里先介绍几种：

- `PDO::FETCH_NUM` 返回索引数组
- `PDO::FETCH_ASSOC` 返回关联数组
- `PDO::FETCH_BOTH` 同时包含上述两种
- `PDO::FETCH_OBJ` 返回对象
- `PDO::FETCH_LAZY` 允许使用三种方法（数值索引、关联和对象）而不会增加内存开销

