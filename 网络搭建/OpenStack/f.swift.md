# Swift

1. 创建一个 siwft

```
swift post xiandian
```



2. 查看创建的 swift 是否成功

```
swift stat xiandian
```



3. 将目录上传到 xiandian 中

```
swift upload xiandian test
```



4. 查看 xiandian 中的文件

```
swift list xiandian
```



5. 将 iaas.txt 文件上传到 xiandian 容器中

```
touch iaas.txt
swift upload xiandian/test iaas.text
```



6. 将 xiandian 容器中的文件下载

```
swift download xiandian text/iaas.tet
```



7. 删除 xiandian 中的文件

```
swift delete xiandian test/iaas.txt
```



8. 删除整个 xiandian

```
swift delete xiandian
```

