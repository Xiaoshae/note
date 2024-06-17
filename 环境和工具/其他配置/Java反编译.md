转会class后删掉Java，使用此命令重新打包成完整的jar

```
jar cvf0m DocToolkit.jar .\DocToolkit\META-INF\MANIFEST.MF -C .\DocToolkit\ .
```

linux

```
jar cvf0m DocToolkit.jar ./DocToolkit/META-INF/MANIFEST.MF -C DocToolkit .
```





将class转换为java

```
java -jar .\fernflower.jar E:\temp\DocToolkit\BOOT-INF\classes\com\example\doctoolkit\shiro\ShiroConfig.class E:\temp\DocToolkit\BOOT-INF\classes\com\example\do`ctoolkit\shiro\
```



将修改后的java转回class

windows java 11

```
javac -d E:\temp\DocToolkit\BOOT-INF\classes -cp "E:\temp\DocToolkit\BOOT-INF\lib\*;E:\temp\DocToolkit\BOOT-INF\classes" E:\temp\DocToolkit\BOOT-INF\classes\com\example\doctoolkit\shiro\ShiroConfig.java
```

linux java 8

```
javac -d /opt/DocToolkit/BOOT-INF/classes/ \
  -cp ":/opt/DocToolkit/BOOT-INF/classes/:/opt/DocToolkit/BOOT-INF/classes/com/example/doctoolkit/shiro/:$(find /opt/DocToolkit/BOOT-INF/lib/ -name "*.jar" | paste -sd ":" -)" \
  /opt/DocToolkit/BOOT-INF/classes/com/example/doctoolkit/shiro/ShiroConfig.java
```





```
PS E:\temp> ls


    目录: E:\temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2024/6/14     20:42                DocToolkit
d-----         2024/6/14     20:33                fernflower
-ar---         2024/6/14     19:18       26737842 DocToolkit-0.0.1-SNAPSHOT.jar
-a----         2024/6/14     20:49       27315593 DocToolkit.jar
-a----         2024/6/14     20:33         245371 fernflower.jar
```

```
PS E:\temp\DocToolkit> ls


    目录: E:\temp\DocToolkit


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2024/3/9     14:18                BOOT-INF
d-----          2024/3/9     14:18                META-INF
d-----          1980/2/1      0:00                org
```



使用的Java版本为 openjdk 11.0.23 2024-04-16

```
PS E:\temp\DocToolkit> java --version
openjdk 11.0.23 2024-04-16
OpenJDK Runtime Environment OpenLogic-OpenJDK (build 11.0.23+9-adhoc..jdk11u)
OpenJDK 64-Bit Server VM OpenLogic-OpenJDK (build 11.0.23+9-adhoc..jdk11u, mixed mode)
```

下载地址：https://builds.openlogic.com/downloadJDK/openlogic-openjdk/11.0.23+9/openlogic-openjdk-11.0.23+9-windows-x64.zip

网站：https://www.openlogic.com/openjdk-downloads



下载fernflower（需要编译）：https://github.com/fesh0r/fernflower

YouTube编译fernflower教程：https://www.youtube.com/watch?v=u2yhAoT1WNM

下载fernflower.jar（直接使用）：https://the.bytecode.club/fernflower.jar





遇到的一些问题：

---

你遇到的问题主要是由于编译环境缺少必要的类库导致的，具体来说是缺少了 Apache Shiro 和 Spring Framework 的类库。当 `javac` 报错找不到特定的类或包时，这通常意味着编译器的类路径（classpath）没有正确设置，无法找到所需的类库。

为了解决这个问题，你需要确保 `javac` 命令的 `-cp` 或 `-classpath` 参数包含了所有必要的库。在你的例子中，你需要确保 `BOOT-INF/lib` 目录下的所有 JAR 文件都被包含在类路径中，这些 JAR 文件应该包含 Apache Shiro 和 Spring Framework 的实现。

以下是修正后的编译命令：

```
javac -d E:\temp\DocToolkit\BOOT-INF\classes -cp "E:\temp\DocToolkit\BOOT-INF\lib\*;E:\temp\DocToolkit\BOOT-INF\classes" E:\temp\DocToolkit\BOOT-INF\classes\com\example\doctoolkit\shiro\ShiroConfig.java
```

---

确保在你的 `MANIFEST.MF` 文件被正确创建并放置后，使用 `jar` 命令时，你需要指向 `META-INF` 目录作为包含 MANIFEST 文件的目录。例如：

```
jar cvfm DocToolkit.jar .\DocToolkit\META-INF\MANIFEST.MF -C .\DocToolkit\ .
```



---

从你提供的旧 JAR 文件和新 JAR 文件运行时的对比输出来看，问题在于新 JAR 文件中的依赖库被压缩了，而 Spring Boot 需要这些依赖库在 JAR 文件内部是未压缩的（即存储而非压缩条目）。这是因为 Spring Boot 需要能够访问这些嵌套的 JAR 文件，而如果它们被压缩，就无法直接读取。

在你使用 `jar` 命令创建 JAR 文件时，你可能没有指定正确的压缩选项，或者使用了默认的压缩级别。默认情况下，`jar` 命令会压缩 JAR 文件内的条目，这对于一般的 JAR 文件是正常的，但对于 Spring Boot 的可执行 JAR 文件，它需要依赖库作为存储条目而非压缩条目。

要解决这个问题，你需要重新打包 JAR 文件，确保 `BOOT-INF/lib` 目录下的所有 JAR 文件作为存储条目而非压缩条目被包含。你可以通过以下方式做到这一点：

```
jar cvf0m DocToolkit.jar .\DocToolkit\META-INF\MANIFEST.MF -C .\DocToolkit\ .
```



---

你遇到的问题是因为你的 **Java 类文件版本（major version 66）不被 Spring Boot 或其相关组件所支持**。Java 类文件的 major version 66 对应于 Java 19。这通常意味着**你的代码是在 Java 19 或更高版本中编译的**，而你正在尝试运行它的环境只支持到 Java 18 或更低版本。

为了解决这个问题，你需要确保你的项目使用了一个与 Spring Boot 和其他依赖库兼容的 Java 版本。**Spring Boot 2.6.13 最初发布时，它支持的最高 Java 版本是 Java 17**。因此，你可能需要将你的项目降级到 Java 17 或更低版本进行编译。



---

看起来你在使用 Java 17 的环境下运行 JAR 文件仍然遇到了 `Unsupported class file major version 66` 的错误。这通常意味着你的项目中的**某些**类或字节码是由**更高版本的 Java 编译器生成的，即 Java 19 或更高版本**。**即使**你当前使用的是 **Java 17 的运行环境**，但这并不足以解决问题，因为你需要确保整个构建过程（包括编译和打包）都使用的是与运行环境相匹配的 Java 版本。



---

从你提供的日志来看，尽管你已经尝试使用 Java 11 来运行应用，但仍然遇到 `Unsupported class file major version 66` 的错误。这意味着 **ShiroConfig 类**的字节码**是由更高版本的 Java 编译器（Java 19 或以上）生成的**。

Java 字节码文件的主版本号对应着不同的 Java 版本：

- 主版本号 65 对应 Java 18
- 主版本号 66 对应 Java 19

因此，当 Spring Boot 尝试读取 ShiroConfig 类的字节码时，它发现这个类是由 Java 19 或更高版本编译的，而你的运行环境仅支持到 Java 11，这就是为什么你看到 `Unsupported class file major version 66` 错误的原因。

要解决这个问题，你需要确保你的**整个项目是在 Java 11 的环境中被正确编译和打包**的。这包括：

**检查依赖库**：确保**所有依赖库都是用 Java 11 或更低版本编译**的。有时候，第三方库可能会使用更高版本的 Java 编译，你需要找到这些库的替代品或旧版本，以确保它们与你的 Java 环境兼容。



这里我需要说一下，我一开始用java 22 。将ShiroConfig.class转为ShiroConfig.java，修改完后，在将ShiroConfig.Java转为ShiroConfig.class。现在是没有发生问题的。

然后我再把这些重新打包成原来的jar。然后去运行这个jar，但是因为编译ShiroConfig.java的时候用的版本是java22。但是Spring Boot不支持这么高的版本，所以不能运行。



然后我换到了更低的版本java17，重新打包。注意，我这里是重新打包，没有重新编译ShiroConfig.java为ShiroConfig.class，我以为是打包的问题，不是编译的问题。

然后我换到了java11的时候，我才发现我还需要重新编译ShiroConfig.java，我重新编译后，后重新打包，最后可以运行了。



然后我将修改后的jar发送给朋友，朋友在反编译ShiroConfig.class看里面的字符串没有被改过。最后问题应该是我电脑上的**文本编辑器**出了问题，我以为修改了base64 token。但是实际上没有被修改。最后我用记事本打开改了，重新编译，重新打包。再反编译看ShiroConfig.class里面的内容，成功改过来了。



最后成功运行了，也不能被攻击了。
