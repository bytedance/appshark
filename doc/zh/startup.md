
## 文档索引
- [1.概述](overview.md)
- [2.如何使用](startup.md)
- [3.规则撰写指南](how_to_write_rules.md)
- [4.如何使用appshark找出程序中的隐私合规问题](how_to_find_compliance_problem_use_appshark.md)
- [5.appshark深入教程](path_traversal_game.md)
- [6.参数配置](argument.md)
- [7.更深入的配置](EngineConfig.md)
- [8.报告格式](result.md)
- [9.常见问题](faq.md)


# 1. 下载jar


[点击下载jar包](https://github.com/bytedance/appshark/releases/download/v0.1.1/AppShark-0.1.1-all.jar). 要求系统安装有jre11环境,

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
java -jar AppShark-0.1.1-all.jar config/config.json5
```

# 5. 查看结果

结果将在当前目录中的out文件,首先是results.json文件,里面给出了所有的漏洞列表. 关于结果的详细解释请查看[result.md](result.md).
如果对某个具体的漏洞有疑问,可以查看url字段指明的文件.



 