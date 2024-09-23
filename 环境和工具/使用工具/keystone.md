# keystone

```
from keystone import *

CODE = b"""ret 100"""

# 创建Keystone对象
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# 汇编代码
encoding, count = ks.asm(CODE)

shellcode = bytes(encoding)

print("Encoded:",encoding)
print("Number:",count)
print("shellcode:",shellcode)

```

