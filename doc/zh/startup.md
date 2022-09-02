如何快速起步,以扫描一个简单的漏洞为例

# 1. 下载jar

[点击下载jar包](https://github.com/bytedance/appshark/releases/download/0.1/AppShark-0.1-all.jar). 要求系统安装有jre11环境,

# 2. 通过github下载config文件夹

```txt
git clone  https://github.com/bytedance/appshark
```

# 3. 修改config文件

1. 将apkPath修改为你想要扫描的apk绝对路径.
2. 指明你要使用的规则,以逗号分隔.并且这些规则应该都放在config/rules目录下. 因为appshark是通过这个路径来查找这些规则的.
3. 指定输出结果保存的目录,默认是当前目录下的out文件,你可以指定一个其他目录.

# 4. 启动appshark

```txt
java -jar AppShark-0.1-all.jar config/config.json5
```

# 5. 查看结果

结果将在当前目录中的out文件,首先是results.json文件,里面给出了所有的漏洞列表. 关于结果的详细解释请查看[result.md](result.md).
如果对某个具体的漏洞有疑问,可以查看url字段指明的文件.



 