# keystone

## 创建项目

创建项目，一个项目就是一个团队或组织。

创建项目的部分参数语法格式：

```
openstack project create [--domain <domain>]
                         [--description <description>]
                         [--enable | --disable]
                         <project-name>
```

`[--domain <domain>]`：项目域名

`--description <description>` ：项目描述

`[--enable | --disable]`：项目状态（启用/禁用）

`<project-name>`：项目名称

示例：



```
openstack project create --domain web --description "web project" --enable web
```



## 创建用户

创建用户

```
openstack user create [--domain <domain>] 
                      [--password <password>]
                      [--email <email-address>]
                      [--description <description>]
                      [--enable | --disable]
                      <name>
```

示例：

```
openstack user create --password root --email xiaoshae@admin.com --domain web web-user
```



## 创建组



1. 创建组

创建一个新的组

```
openstack group create [--domain <domain>] [--description <description>] [OTHER OPTIONS] <group-name>
```



2. 删除组

删除一个组

```
openstack group delete <group-id-or-name>
```



3. 列出所有组

查看所有的组。

```
openstack group list [OPTIONS]
```



4. 详细的查看组

显示指定组的详细信息

```
openstack group show <group-id-or-name>
```



5. 添加用户到组

添加一个用户到一个组中。

```
openstack group add user <group-id-or-name> <user-id-or-name>
```



6. 从组中移除用户

将一个用户从一个组中移除。

```
openstack group remove user <group-id-or-name> <user-id-or-name>
```



7. 检查某个用户是否存在组中

查看某个用户是否存在在某个组中。

```
openstack group contains user <group-id-or-name> <user-id-or-name>
```



## 创建角色

1. **创建角色**

使用`role create`命令来创建一个新的角色。

```
openstack role create <role-name>
```



2. **列出所有角色**

使用`role list`命令来查看当前OpenStack环境中存在的所有角色。

```
openstack role list
```



3. **显示角色详情**

使用`role show`命令来获取指定角色的详细信息。

```
openstack role show <role-id-or-name>
```



4. **添加角色给用户**

使用`role add`命令将一个角色赋予某个用户在特定项目中的权限。

```
openstack role add --user <user-name> --project <project-name> <role-name>
```



5. **移除用户的角色**

如果需要撤销用户的某项权限，可以使用`role remove`命令。

```
openstack role remove --user <user-name> --project <project-name> <role-name>
```



6. **修改角色**

如果需要更新角色的信息，可以使用`role set`命令。

```
openstack role set --name <new-role-name> <role-id-or-old-name>
```



7. **删除角色**

当不再需要某个角色时，可以使用`role delete`命令来删除它。

```
openstack role delete <role-id-or-name>
```



## 操作示例 cli

1. 在 controller 上设置环境变量（认证）

```
source /etc/keystone/admin-openrc.sh
```



2. 创建一个项目（租户）

```
openstack project create --domain=demo project1
```



3. 创建一个用户，并指定项目为 project1（刚刚创建的）

```
openstack user create --domain=demo --password=user-pass --email=user@user.com --project=project1 user1
```



4. 创建一个角色

```
openstack role create role1
```



5. 将用户绑定到角色

```
openstack role add --user user1 --project project1 role1
```



6. 创建一个组

```
openstack group create --domain=demo group1
```



7. 将用户添加到组中

```
openstack group add user group1 user1
```



## 操作示例 gui

1. 创建一个项目

![image-20241230102535438](./images/b.keystone%20%E8%AE%A4%E8%AF%81.assets/image-20241230102535438-1735525950232-9.png)



2. 创建一个角色

![image-20241230102637700](./images/b.keystone%20%E8%AE%A4%E8%AF%81.assets/image-20241230102637700-1735525940133-6.png)



3. 创建一个用户

![image-20241230102725849](./images/b.keystone%20%E8%AE%A4%E8%AF%81.assets/image-20241230102725849.png)



4. 创建一个组

![image-20241230102749530](./images/b.keystone%20%E8%AE%A4%E8%AF%81.assets/image-20241230102749530.png)



5. 将用户加入组

![image-20241230102813415](./images/b.keystone%20%E8%AE%A4%E8%AF%81.assets/image-20241230102813415.png)

![image-20241230102845682](./images/b.keystone%20%E8%AE%A4%E8%AF%81.assets/image-20241230102845682.png)

