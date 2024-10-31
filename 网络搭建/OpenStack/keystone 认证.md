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



## 创建角色

角色限定了用户的操作权限。

```
openstack role create <name>
```

示例：

```
openstack role create web-role
```



绑定用户和项目分配

```
openstack role add --user <username> --project <projectname> <roleName>
```

示例：

```
openstack role add --user web-user --project web web-role
```

