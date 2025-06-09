# 数字证书和 PKI

## 概念

### 非对称密钥

**非对称加密（Asymmetric Key Cryptography）**的核心原理在于：**生成一对数学关联的密钥（密钥 A 和密钥 B），并确保它们具有单向解密的特性——即用密钥 A 加密的数据只能通过密钥 B 解密，反之亦然。**

- **公钥（Public Key）**：可以公开分发的密钥，用于加密数据或验证签名，任何人都可以使用。
- **私钥（Private Key）**：严格保密，仅由密钥持有者保存，用于解密数据或生成签名。



非对称加密算法在生成密钥对时，会基于特定的数学运算生成两把密钥。**公钥和私钥在生成时就已具备明确的数学关联和功能区分**，它们是本质不同的文件。以 RSA 算法为例，**私钥**包含**关键素数 p 和 q**，而**公钥**则由**模数 n = p · q 和公钥指数 e** 组成。



### 数字证书

数字证书（Digital Certificate）是一种**用于证明身份和确保通信安全**的**电子文档**。证书是一个结构化的文件，包含公钥、持有者的身份信息（如域名、组织名称）、颁发者信息、有效期等，并由 CA 使用其私钥签名以证明可信。

在实际应用中，数字证书、TLS 证书或简称证书**通常都指代这种 X.509 格式的文件**。



X.509 证书的结构由三个主要部分组成：证书主体（TBSCertificate）、签名算法标识和签名值。



以下是一个标准的 x509 终端证书：

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            05:bf:65:ff:fe:50:af:c1:e3:c0:6b:2a:5b:0e:d9:ad:05:34
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Let's Encrypt, CN=R11
        Validity
            Not Before: May  9 01:05:37 2025 GMT
            Not After : Aug  7 01:05:36 2025 GMT
        Subject: CN=*.xiaoshae.cn
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d9:d5:22:a4:b8:10:5d:7c:be:fe:5e:ec:8e:b1:
                    9f:c5:f6:5f:54:9d:f8:86:9f:fc:eb:1a:2b:0c:f1:
                    8b:69:16:ec:b0:d4:17:01:65:7a:5d:50:9b:d4:74:
                    97:e0:94:86:97:d0:a5:74:7b:db:28:d0:97:6e:97:
                    59:8e:37:4e:68:97:b8:30:38:04:38:93:ca:50:3d:
                    8e:6a:31:3d:21:56:21:40:57:b3:71:09:49:75:cb:
                    5d:14:cb:4a:8f:91:1f:d3:fc:f2:c5:3f:cd:61:1b:
                    9f:8b:3f:85:4f:90:21:71:52:98:f3:3f:a5:01:db:
                    11:2c:b1:77:db:7c:56:5b:96:5a:29:3c:ab:0b:d5:
                    4a:d8:6f:a4:1b:e5:3b:87:1b:4d:49:ee:cd:37:c7:
                    42:2d:a0:06:38:6c:1b:94:56:da:d6:22:35:01:79:
                    ac:46:e5:4f:5f:13:57:50:13:03:c5:43:8d:56:a8:
                    ff:02:6d:6f:30:1d:70:dd:d2:f2:5f:eb:f2:a2:25:
                    d8:3e:eb:3e:0a:40:1a:b1:af:bb:4f:47:87:1e:af:
                    b9:c4:ec:64:76:79:48:a2:81:83:2a:d8:f1:21:cf:
                    2f:d0:41:cd:b6:40:79:fa:f5:65:48:3e:32:c6:36:
                    b7:67:c7:ed:56:e4:b9:73:b9:69:f0:49:d9:b7:7d:
                    a6:9f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                CF:86:22:D5:73:E4:0A:86:FF:DC:28:4C:E2:F3:BA:92:96:51:17:76
            X509v3 Authority Key Identifier:
                C5:CF:46:A4:EA:F4:C3:C0:7A:6C:95:C4:2D:B0:5E:92:2F:26:E3:B9
            Authority Information Access:
                CA Issuers - URI:http://r11.i.lencr.org/
            X509v3 Subject Alternative Name:
                DNS:*.xiaoshae.cn, DNS:xiaoshae.cn
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://r11.c.lencr.org/53.crl
            CT Precertificate SCTs:
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 1A:04:FF:49:D0:54:1D:40:AF:F6:A0:C3:BF:F1:D8:C4:
                                67:2F:4E:EC:EE:23:40:68:98:6B:17:40:2E:DC:89:7D
                    Timestamp : May  9 02:04:07.964 2025 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:20:59:BE:36:DF:E0:DC:A9:A6:0E:BC:9B:59:
                                A9:0D:F5:6C:21:BB:0D:CB:9F:FA:B4:E8:9C:61:4A:4D:
                                A5:71:1A:0C:02:21:00:BE:D9:BE:C6:77:27:5D:39:28:
                                E9:0B:DF:ED:D7:2D:58:12:31:6D:73:64:CA:2F:27:04:
                                8B:2F:5C:09:C4:91:67
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : ED:3C:4B:D6:E8:06:C2:A4:A2:00:57:DB:CB:24:E2:38:
                                01:DF:51:2F:ED:C4:86:C5:70:0F:20:DD:B7:3E:3F:E0
                    Timestamp : May  9 02:04:09.442 2025 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:06:F3:07:DA:CB:3D:1E:C1:1E:E2:FD:7B:
                                F2:63:96:8F:E6:D0:13:6D:5C:63:1E:E9:6C:F6:5C:C2:
                                78:B7:FF:9B:02:20:46:49:9A:52:32:A4:93:24:8F:50:
                                F1:61:C7:B0:27:41:15:4D:88:19:80:15:99:7D:63:1B:
                                13:06:07:6B:DE:B9
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        31:4e:7b:07:d5:25:e0:be:91:4e:ff:d9:b5:59:7e:77:62:44:
        46:92:09:4a:b6:55:6c:16:01:c7:5c:ee:9a:9e:0f:e5:4b:92:
        4d:28:de:56:4f:e7:49:1e:b5:2e:eb:05:9d:28:cb:95:39:85:
        f3:b6:75:53:d6:b4:5c:2d:b4:c9:01:bd:d0:42:0f:cc:1c:4d:
        bc:67:94:37:67:15:c9:67:5d:f3:e0:62:56:84:a7:d8:7c:3b:
        fa:3a:e6:ea:96:5e:82:e4:71:cc:59:ac:5c:0a:30:ad:49:5b:
        aa:12:7a:83:ea:a5:78:61:e9:8b:3e:72:ef:be:62:d3:40:76:
        32:4a:df:c0:3e:a2:c1:29:51:89:aa:56:fe:74:54:c1:d6:de:
        4c:ba:1b:97:bf:20:74:11:8a:a0:f7:76:f5:a3:06:1a:24:0f:
        72:d2:28:38:c7:b5:90:be:2a:7e:c6:97:1f:b9:64:99:7e:74:
        b9:70:32:87:a3:dc:ef:59:c6:e0:f2:5b:1a:9d:bd:2c:91:39:
        00:22:6f:1f:83:4c:10:97:79:3e:7d:b3:b7:01:0d:3f:9a:b5:
        70:fe:a1:3a:92:db:04:6c:07:63:0f:68:1d:52:a6:d0:f7:31:
        f8:92:cc:c1:c7:a1:d0:c9:50:fa:03:44:d8:6a:e0:3b:6f:a7:
        fc:c1:5b:a2
```

标准 **x509 证书** 主要由三部分组成：**证书主体（TBS Certificate）**、**签名算法（Signature Algorithm）** 和 **签名值（Signature Value）**。

如果严格按照字段层级进行分类，则为**证书主体**（对应 Data）、**签名算法**（**Signature Algorithm**）和**签名值**（**Signature Value**）。 

其中，公钥部分是证书主体中的一个子字段。



**证书主体**

```
Data:
    Version: 3 (0x2)
    Serial Number:
        05:bf:65:ff:fe:50:af:c1:e3:c0:6b:2a:5b:0e:d9:ad:05:34
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=US, O=Let's Encrypt, CN=R11
    Validity
        Not Before: May  9 01:05:37 2025 GMT
        Not After : Aug  7 01:05:36 2025 GMT
    Subject: CN=*.xiaoshae.cn
```

Version（版本号）：表示证书的 X.509 版本号。当前值为 3（最新）。

Serial Number（序列号）：数字证书的唯一标识符，该序列号随机生成。由证书颁发机构生成。

Signature Algorithm（签名算法）：**证书颁发机构**声明对当前证书签名时使用的算法。Data 外部为证书颁发机构签名时实际使用的算法。两者通常相同。

Issuer（颁发者）：签发此证书的**证书颁发机构的信息**。通常为上层证书的 **Subject**。根证书 Issuer 与 Subject 值相同。

Validity（有效期）：证书的有效时间范围，包含生效时间 (Not Before) 和到期时间 (Not After)。

- Not Before：生效时间
- Not After：到期时间

Subject（主体）：证书持有者的标识。



**公钥部分**

Subject Public Key Info 包含证书持有者的公钥信息，包括公钥算法和公钥本身。

```
Subject Public Key Info:
    Public Key Algorithm: rsaEncryption
        Public-Key: (2048 bit)
        Modulus:
            00:d9:d5:22:a4:b8:10:5d:7c:be:fe:5e:ec:8e:b1:
            ...（共2048位，256字节）...
        Exponent: 65537 (0x10001)
```

Public Key Algorithm（算法标识）：公钥使用的加密算法，这里是 RSA。

Public-Key（密钥长度）：标识密钥的长度，实际不包含在证书中，而是通过 Modulus 计算得出。

Modulus（模数）：RSA的 `n` 值（大整数，此处为2048位）

Exponent（指数）：RSA的 `e` 值（通常为65537）



**扩展字段**

这是 X.509 版本 3 引入的扩展字段，提供了额外的功能和信息。

```
X509v3 extensions:
    X509v3 Key Usage: critical
        Digital Signature, Key Encipherment
    X509v3 Extended Key Usage:
        TLS Web Server Authentication, TLS Web Client Authentication
    X509v3 Basic Constraints: critical
        CA:FALSE
    X509v3 Subject Key Identifier:
        CF:86:22:D5:73:E4:0A:86:FF:DC:28:4C:E2:F3:BA:92:96:51:17:76
    X509v3 Authority Key Identifier:
        C5:CF:46:A4:EA:F4:C3:C0:7A:6C:95:C4:2D:B0:5E:92:2F:26:E3:B9
    Authority Information Access:
        CA Issuers - URI:http://r11.i.lencr.org/
    X509v3 Subject Alternative Name:
        DNS:*.xiaoshae.cn, DNS:xiaoshae.cn
    X509v3 Certificate Policies:
        Policy: 2.23.140.1.2.1
    X509v3 CRL Distribution Points:
        Full Name:
            URI:http://r11.c.lencr.org/53.crl
    CT Precertificate SCTs:
        Signed Certificate Timestamp:
            Version   : v1 (0x0)
            Log ID    : 1A:04:FF:49:D0:54:1D:40:AF:F6:A0:C3:BF:F1:D8:C4:
                        67:2F:4E:EC:EE:23:40:68:98:6B:17:40:2E:DC:89:7D
            Timestamp : May  9 02:04:07.964 2025 GMT
            Extensions: none
            Signature : ecdsa-with-SHA256
                        30:45:02:20:59:BE:36:DF:E0:DC:A9:A6:0E:BC:9B:59:
                        ...
        Signed Certificate Timestamp:
            Version   : v1 (0x0)
            Log ID    : ED:3C:4B:D6:E8:06:C2:A4:A2:00:57:DB:CB:24:E2:38:
                        01:DF:51:2F:ED:C4:86:C5:70:0F:20:DD:B7:3E:3F:E0
            Timestamp : May  9 02:04:09.442 2025 GMT
            Extensions: none
            Signature : ecdsa-with-SHA256
                        30:44:02:20:06:F3:07:DA:CB:3D:1E:C1:1E:E2:FD:7B:
                        ...
```

Key Usage（公钥用途）：指定证书公钥的用途，值 **Digital Signature, Key Encipherment**。这里允许用于数字签名和密钥加密。

Extended Key Usage（扩展公钥用途）：进一步指定公钥的用途，值 **TLS Web Server Authentication, TLS Web Client Authentication** 表示证书可用于 TLS 服务器身份验证和客户端身份验证。

Basic Constraints（基本约束）：指示该证书是否为 CA 证书，此处为 FALSE，表示这不是 CA 证书。防止该证书被用作 CA 来签发其他证书，增强安全性。

Subject Key Identifier（ SKI 主体密钥标识符）：证书中公钥的唯一标识符，通常是公钥的哈希值。

Authority Key Identifier（AKI 授权密钥标识符）：标识签发该证书的 CA 公钥的唯一标识符。

Authority Information Access（AIA）：提供 CA 证书的下载地址。

Subject Alternative Name（SAN）：列出证书适用的其他域名（SAN），包括通配符域名和主域名。扩展证书的适用范围，允许证书用于多个域名，现代浏览器通常优先检查 SAN 而非 Subject CN。

Certificate Policies：指定证书遵循的策略，值 **Policy: 2.23.140.1.2.1** 是 Let's Encrypt 的策略，符合 CA/Browser Forum 的域验证 (DV) 证书要求。

CRL Distribution Points：提供证书吊销列表 (CRL) 的下载地址。允许客户端检查证书是否被吊销。

CT Precertificate SCTs：证书透明性 (Certificate Transparency, CT) 的签名时间戳，证明证书已记录到 CT 日志中。增强证书透明性，防止未经授权的证书签发，现代浏览器要求 HTTPS 证书包含 SCT。





**SKI 扩展详解**

在 x509 v3 版本中存在一个 **Subject Key Identifier (SKI)** 扩展，该扩展字段的值类型一般为 SHA-1 哈希值，或直接取公钥的密钥标识符。标识当前证书的**公钥唯一性**。

```
X509v3 Authority Key Identifier:
    C5:CF:46:A4:EA:F4:C3:C0:7A:6C:95:C4:2D:B0:5E:92:2F:26:E3:B9
```



对于 RSA 密钥类型，**SKI** 值为 RSA公钥的 Modulus 和 Exponent 的 SHA-1 哈希值，以下式计算过程：

1. **将公钥的 `Modulus` 和 `Exponent` 编码为 DER 格式**（遵循 ASN.1 规则）。
2. **对 DER 编码后的二进制数据计算 SHA-1 哈希值**，结果即为 **SKI**。



**签名算法与签名值**

**签名原理**：

1. 将**证书主体（TBS Certificate）**转换为 ASN.1 DER 格式的二进制数据。
2. 对二进制数据计算其哈希值（此证书签名算法使用 **SHA-256** 哈希算法）。
3. 使用**私钥对计算出的哈希值进行加密**，加密后的结果即构成了证书中的 **Signature Value 字段的内容**。

**证书中不存储原始哈希值**，仅存储加密后的签名值（即 `Signature Value`）。**验证时**，验证方需要**自行对 TBS Certificate 进行 DER 编码并计算其哈希值**。



**验证原理**：

- **从当前证书的 `Issuer` 字段中获取其上一级数字证书**，并从中提取出用于验证的公钥（例如，此处为 Let's Encrypt R11 的公钥）。
- 将当前证书中的**证书主体（TBS Certificate）转换为 ASN.1 DER 格式的二进制数据**。
- 依据证书中指明的**签名算法（Signature Algorithm）**，对这个 DER 编码后的数据计算其哈希值（此证书为 SHA-256 算法）。
- 利用之前获取到的上一级证书的公钥，**解密当前证书的 `Signature Value` 字段，从而得到原始的哈希值**。
- 将解密得到的原始哈希值与重新计算的哈希值进行比对。**若两者一致，则表明该证书的签名有效**。





**证书链**：

在数字证书中，**上层证书不会完整嵌入在当前证书中**，而是通过引用关联。**确定上一层级证书（即颁发者CA的证书）**主要通过以下字段和机制实现：



**Issuer 字段**

声明当前证书的颁发者身份（即上层数字证书的信息）。

```
Issuer: C=US, O=Let's Encrypt, CN=R11
```



**AKI 扩展**

Authority Key Identifier 扩展标识**上层数字证书的公钥**，此扩展的值为**上层数字证书的 SKI**。

```
X509v3 Authority Key Identifier:
    C5:CF:46:A4:EA:F4:C3:C0:7A:6C:95:C4:2D:B0:5E:92:2F:26:E3:B9
```



**AIA 扩展**

**Authority Information Access (AIA) 扩展** 用于指定证书链中**上一层数字证书的下载地址**，其值为一个 **URL**。

```
Authority Information Access:
    CA Issuers - URI:http://r11.i.lencr.org/
```







## PKI

**公钥基础设施**是一套**用于管理数字证书和公钥加密的系统**，其核心组件包括：

- **证书颁发机构（CA）**：负责颁发和撤销数字证书。
- **注册机构（RA）**：协助 CA 验证申请者的身份。
- **数字证书**：基于 X.509 标准，包含公钥、身份信息和 CA 签名。
- **私钥和公钥**：用于加密、解密和签名。
- **证书撤销列表（CRL）**：记录被撤销的证书。
- **信任链**：由根 CA、中间 CA 和终端实体证书组成。



OpenSSL 提供了实现上述组件的工具，允许用户创建自己的 CA、管理证书生命周期、生成 CRL 并验证信任链。



### 非对称密钥

OpenSSL 提供了多个命令用于生成非对称密钥（私钥和公钥）以及相关参数，主要涉及以下命令：

早期 OpenSSL 使用专用命令**（genrsa / gendsa / ecparam）**生成密钥，操作分散且复杂。现代版本改用通用命令 **genpkey**（支持多种算法）和 **pkey**（统一管理密钥），简化流程并提高灵活性。**pkeyutl** 取代 **rsautl** 实现通用加密/签名，整体设计更简洁高效。



#### genpkey

openssl genpkey 是一个用于生成私钥或密钥对的通用命令，支持多种公钥算法（如 RSA、EC、DSA、DH 等），是 OpenSSL 中推荐的非对称密钥生成工具，取代了旧的专用命令（如 genrsa、gendsa）。以下是其所有参数的详细说明：



**-config configfile**

指定配置文件，覆盖默认的 **openssl.cnf**。

配置文件可定义默认参数、算法选项等，详见 config(5)。

```
openssl genpkey -algorithm RSA -out key.pem -config custom.cnf
```



**-outpubkey filename**

将公钥输出到指定文件。

如果未指定，公钥不会单独输出。

```
openssl genpkey -algorithm RSA -out key.pem -outpubkey pubkey.pem
```



**-out filename**

指定私钥或参数的输出文件。

如果未指定，输出到标准输出（stdout）。

```
openssl genpkey -algorithm RSA -out key.pem
```



**-outform DER|PEM**

指定输出格式，PEM（文本格式，Base64 编码）或 DER（二进制格式）。默认：PEM。

仅适用于密钥输出，**使用 -genparam 生成参数时，-outform 被忽略，输出格式固定为 PEM**。PEM 格式更常见，易于阅读和传输。

```
openssl genpkey -algorithm RSA -out key.der -outform DER
```



**-verbose**

在生成密钥时显示“状态点”（progress dots），表示生成进度。

```
openssl genpkey -algorithm RSA -verbose -out key.pem
```



**-quiet**

禁止显示“状态点”，保持输出简洁。

```
openssl genpkey -algorithm RSA -quiet -out key.pem
```

与 **-verbose** 互斥，适合脚本或自动化任务。



**-pass arg**

指定输出私钥的加密密码来源。

与 **-cipher** 配合使用，加密私钥以增强安全性。

参考 openssl-passphrase-options(1)，支持格式如 pass:password、env:var、file:filename 等。

```
openssl genpkey -algorithm RSA -out key.pem -cipher aes256 -pass pass:secure123
```



**-cipher**

指定加密私钥时使用的对称加密算法（如 aes256、des3）。

需要与 **-pass** 配合使用，加密算法必须是 **EVP_get_cipherbyname()** 支持的算法。

```
openssl genpkey -algorithm RSA -out key.pem -cipher aes256 -pass pass:secure123
```



**-algorithm alg**

指定使用的公钥算法。支持的算法：

- 私钥生成：RSA、RSA-PSS、EC、X25519、X448、ED25519、ED448。
- 参数生成（需配合 -genparam）：DH、DSA、EC。

```
openssl genpkey -algorithm EC -out eckey.pem
```

必须在 -pkeyopt 之前指定。与 -paramfile 互斥。



**-genparam**

生成算法参数而非私钥。

**支持的算法**：DH、DSA、EC。

必须在 **-algorithm、-paramfile 或 -pkeyopt** 之前指定。生成的参数可用于后续密钥生成。

```
openssl genpkey -genparam -algorithm DH -out dhparam.pem
```



**-paramfile filename**

指定参数文件，用于基于已有参数生成私钥。

```
openssl genpkey -paramfile dsaparam.pem -out dsakey.pem
```

与 -algorithm 互斥，参数文件决定算法类型。



**-text**

以明文形式打印私钥、公钥或参数的详细信息（不加密），连同 PEM 或 DER 结构。

```
openssl genpkey -algorithm RSA -out key.pem -text
```





**-pkeyopt opt:value**

设置特定算法的选项，具体选项因算法而异。

```
openssl genpkey -algorithm RSA -out key.pem \
    -pkeyopt rsa_keygen_bits:4096 \
    -pkeyopt rsa_keygen_primes:3
```

可通过 **openssl genpkey -algorithm XXX -help** 查看某算法支持的选项。详见下文的“密钥生成选项”和“参数生成选项”。



**RSA 密钥生成选项**

**rsa_keygen_bits:numbits**

指定 	RSA 密钥的位数，**默认值为 2048 位。**建议至少使用 2048 位，推荐 3072 或 4096 位以增强安全性。

用法示例：**-pkeyopt rsa_keygen_bits:3072**。



**rsa_keygen_primes:numprimes**

设置生成 RSA 密钥的素数个数，默认为 2。多素数 RSA 可提升密钥生成速度，但需注意安全性评估。

用法示例：**-pkeyopt rsa_keygen_primes:3**。



**rsa_keygen_pubexp:value** 

指定 RSA 公钥指数，默认值为 65537。支持十进制或十六进制（如 0x 前缀），常用值为 3 或 65537。

用法示例：**-pkeyopt rsa_keygen_pubexp:3**。



**EC 密钥生成选项**

**ec_paramgen_curve:curve**

指定椭圆曲线名称，支持 NIST 标准曲线如 P-256（secp256r1）、P-384（secp384r1）等。

用法示例：**-pkeyopt ec_paramgen_curve:P-256**。

查看完整曲线列表可使用命令：**openssl ecparam -list_curves**。



**ec_param_enc:encoding**

设置椭圆曲线参数的编码格式，默认为 **named_curve**（仅引用曲线名称），也可选 **explicit**（包含完整参数）。

用法示例：**-pkeyopt ec_param_enc:named_curve**。





私钥能推导出公钥，本质上是**通过私钥的数学参数计算出公钥**，私钥中存储了生成公钥所需的全部信息。



#### pkey

`openssl pkey` 是 OpenSSL 工具集中的一个核心组件，专门用于处理公钥和私钥。**它支持多种功能**，包括密钥格式转换、密钥验证、加密解密操作以及密钥信息提取等，适用于各类密钥管理场景。

该命令的选项可分为三大类：**通用选项**用于设置基础操作参数，**输入选项**用于指定密钥来源及其格式，**输出选项**则控制密钥的导出方式及内容展示。



**通用选项**

**-check**

此选项用于检查密钥对中公钥和私钥组件的一致性。

主要用于检查私钥的数学一致性，**不适用于公钥**。



**-pubcheck**

此选项用于检查公钥或密钥对中公钥组件的正确性。

仅适用于某些特定算法（如 DSA、ECDSA），**不适用于 RSA 公钥**。



**输入选项**

**-in filename|uri** 

指定输入文件或 URI，包含要处理的公钥或私钥。如果未指定，默认为标准输入。 如果输入的密钥是加密的且未提供 -passin，会提示输入密码。



**-inform DER|PEM|P12|ENGINE**

指定输入密钥的格式，默认根据文件内容自动检测。

- PEM：Base64 编码的文本格式（常见）。
- DER：二进制格式。
- P12：PKCS#12 格式（常用于证书和密钥的打包）。
- ENGINE：通过加密引擎加载密钥。



**-passin arg**

指定输入密钥的密码来源。格式见 **openssl-passphrase-options(1)**，常见格式包括：

- **pass:password**：直接指定密码。
- **file:filename**：从文件中读取密码。
- **env:var**：从环境变量读取密码。
   示例：-passin pass:secret123



**-pubin**

指定输入文件为公钥（而不是默认的私钥）。如果输入仅包含私钥，会自动提取其公钥部分。



**输出选项**

**-out filename**

指定输出文件，保存编码后的密钥或文本信息。如果未指定，输出到标准输出。

**注意**：输出文件会覆盖输入文件（如果文件名相同），但文件 I/O 非原子操作。



**-outform DER|PEM**

指定输出密钥的格式，默认是 PEM。

- PEM：文本格式，适合大多数应用场景。
- DER：二进制格式，常用于需要严格格式的场景。



**-cipher**

使用指定的加密算法加密输出的 PEM 私钥（如 aes128、des3）。需要结合 **-passout** 提供密码。

**注意**：DER 格式不支持加密。



**-passout arg**

指定输出文件的密码来源，格式同 -passin。

示例：**-passout pass:secret123**



**-traditional**

使用传统的私钥格式，而非默认的 PKCS#8 格式。

PKCS#8 是更现代的格式，支持多种算法和加密。



**-pubout**

仅输出公钥部分（即使输入包含私钥）。与 **-text** 结合时，等效于 **-text_pub**。

未指定 **-pubout** 参数则输出内容为私钥，如果指定 **-pubout** 参数则输出内容为公钥。无法同时输出公钥和私钥。



**-text**

以明文形式输出密钥的详细信息（如 RSA 的模数、指数或 EC 的参数）。可与编码输出结合，但不能与 DER 格式结合。



**-text_pub**

仅输出公钥部分的明文信息，不能与 DER 格式结合。



**-noout**

不输出编码后的密钥，仅输出文本信息（需结合 **-text** 或 **-text_pub**）。

- 仅使用 **-text**（未指定 **-noout**）：输出 PEM 格式密钥及明文信息。
- 同时使用 **-text 和 -noout**：仅输出明文信息，不显示 PEM 格式密钥。
- 单独使用 **-noout**（未指定 **-text** 或 **-text_pub**）：无任何输出。





**-ec_conv_form arg**

（仅限椭圆曲线密钥）指定椭圆曲线点的编码格式：

- compressed（默认）：压缩格式，占用空间小。
- uncompressed：未压缩格式，包含完整点坐标。
- hybrid：混合格式。

 **注意**：由于专利问题，二进制曲线的压缩格式默认禁用，需在编译时定义 OPENSSL_EC_BIN_PT_COMP 启用。



**-ec_param_enc arg**

（仅限椭圆曲线密钥）指定椭圆曲线参数的编码方式：

- named_curve（默认）：使用曲线 OID（如 secp256r1）。
- explicit：显式编码曲线参数（如素数、生成点等）。

**注意**：implicitlyCA 目前未实现。



#### x509

openssl x509 是一个多功能的证书处理命令，用于显示、转换、编辑信任设置、生成证书或证书请求，并支持自签名或作为“微型CA”签名。



**输入、输出和通用选项**

**-in filename|uri**

指定输入文件或 **URI**，读取证书或证书请求（与 **-req** 配合使用）。默认从标准输入读取。 

注意：不能与 **-new** 选项一起使用。



**-passin arg**

指定输入文件（如私钥或证书）的密码来源。



**-new**

从头生成一个新证书，而不是基于现有证书或请求。需配合 -set_subject 指定主体名称，公钥可通过 -force_pubkey 指定，默认使用 -key 或 -signkey 提供的密钥（自签名）。



**-x509toreq**

将证书转换为PKCS#10证书请求，需使用 -key 或 -signkey 提供私钥进行自签名，公钥放入请求的 subjectPKInfo 字段。

默认不复制输入证书的扩展，可通过 -extfile 添加扩展。



**-req**

指定输入为PKCS#10证书请求（默认期望输入为证书）。请求需自签名，扩展默认不复制，可通过-extfile指定。



**-copy_extensions arg**

处理从证书到请求（-x509toreq）或从请求到证书（-req）的扩展复制行为：

- none：忽略扩展（默认）。
- copy 或 copyall：复制所有扩展（生成请求时不复制主体标识和颁发者密钥标识扩展）。可结合 -ext 进一步限制复制的扩展。



**-inform DER|PEM**

指定输入文件格式，默认为PEM。支持DER或PEM。



**-vfyopt nm:v**

传递验证操作的签名算法选项，具体名称和值因算法而异。



**-key filename|uri / -signkey filename|uri**

指定用于签名新证书或请求的私钥，公钥自动放入证书或请求（除非使用 **-force_pubkey** ）。

- 设置颁发者名称为主体名称（自颁发）。
- 除非使用 -preserve_dates，否则有效期起始时间为当前时间，结束时间由 -days 决定。
- 不能与 -CA 一起使用。-signkey是-key的别名。



**-keyform DER|PEM|P12|ENGINE** 

指定私钥输入格式，默认未指定。



**-out filename**

指定输出文件名，默认输出到标准输出。



**-outform DER|PEM**

指定输出格式，默认PEM。



**-nocert**

不输出证书内容，仅输出由其他选项（如打印选项）请求的内容。



**-noout**

禁止输出，仅打印由其他选项（如-text、-serial等）指定的信息。



**证书输出选项**

**-set_serial n**

设置证书序列号（十进制或以 0x 开头的十六进制）。可与 -key、-signkey 或 -CA 一起使用。若与 -CA 一起使用，则不使用 -CAserial 指定的序列号文件。



**-next_serial**

将序列号设置为输入证书序列号加1。



**-not_before date**

显式设置证书生效日期，格式为 **YYMMDDHHMMSSZ（ASN1 UTCTime）**或 **YYYYMMDDHHMMSSZ（ASN1 GeneralizedTime）**，或 **today**。不能与 **-preserve_dates** 一起使用。



**-not_after date**

显式设置证书到期日期，格式同上。不能与 **-preserve_dates** 一起使用，优先于 **-days**。



**-days arg**

设置新证书从今天起的有效期（天数），默认 30 天。

不能与 **-preserve_dates** 或 **-not_after** 一起使用。



**-preserve_dates**

签名时保留输入证书的 **notBefore** 和 **notAfter** 日期，不能与 **-days、-not_before** 或 **-not_after** 一起使用。



**-set_issuer arg**

设置证书的颁发者名称，格式同 **-set_subject**。



**-set_subject arg / -subj arg**
设置证书的主体名称，格式为`/type0=value0/type1=value1/...`，支持反斜杠转义特殊字符，空值允许，多值RDN用+分隔。

例如：`/DC=org/DC=OpenSSL/DC=users/UID=123456+CN=John Doe`

可与 **-new** 和 **-force_pubkey** 一起使用生成新证书。

**-subj** 是 **-set_subject** 的别名。



**-force_pubkey filename**

设置证书或请求的公钥为指定文件中的公钥，而不是输入或 -key 中的公钥。适用于生成自颁发但非自签名的证书（如DH密钥）。



**-clrext**

生成新证书或请求时，不保留输入的扩展。生成请求时，主体标识和颁发者密钥标识扩展不包含。



**-extfile filename**

指定包含X.509扩展的配置文件。



**-extensions section**

指定 **-extfile** 中要添加的扩展部分，详见 x509v3_config(5) 。



**-sigopt nm:v**

签名操作时传递给签名算法的选项，可多次使用，具体选项因算法而异。



**-badsig**

签名时故意破坏签名，用于测试。



**-digest**

指定签名或指纹计算的摘要算法（如SHA1、SHA256），影响-fingerprint、-key、-CA等选项。默认指纹用SHA1，签名用算法默认摘要（通常SHA256）。
