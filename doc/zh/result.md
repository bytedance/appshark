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


# result 解读
 

首先需要说明的是results.json设计的目的就是为了方便程序处理而不是人工阅读. 我们重点关注的是SecurityInfo和ComplianceInfo字段.

## SecurityInfo

这里的安全漏洞会根据你在规则中`desc`指定的`category`和`name`进行分类. 方便程序处理,也方便人工阅读.
其中`vulners`字段是这种类型漏洞的列表. 其中每个漏洞都有一个hash字段,该字段可以认为是漏洞的唯一标识.
details字段包含了漏洞的大量信息:

- Source 规则中source字段匹配到的变量.
- Sink 规则中sink字段匹配到的变量
- position source对应变量所在的函数
- entryMethod 分析的入口
- target 污点在变量之间传播的过程.
- url 以html格式展示的污点在变量之间传播的过程.

## ComplianceInfo

ComplianceInfo专门针对隐私合规问题. 如果category是`ComplianceInfo`,那么appshark将会到其特殊处理.比如:

```json
{
  "desc": {
    "name": "GAID_NetworkTransfer_body",
    "detail": "存在<GAID>[获取]相关操作通过网络发送-body",
    "category": "ComplianceInfo",
    "complianceCategory": "PersonalDeviceInformation_NetworkTransfer",
    "complianceCategoryDetail": "个人设备信息_NetworkTransfer",
    "level": "3"
  }
}
```

其分类将是:

- 第一级是ComplianceInfo
- 第二级是ComplianceCategory指定的PersonalDeviceInformation_NetworkTransfer
- 第三级是name指定的GAID_NetworkTransfer_body.

比如:

```json
{
  "ComplianceInfo": {
    "PersonalDeviceInformation_NetworkTransfer": {
      "GAID_NetworkTransfer_body": {
        "category": "ComplianceInfo",
        "detail": "存在<GAID>[获取]相关操作通过网络发送-body",
        "name": "GAID_NetworkTransfer_body",
        "vulners": [],
        "deobfApk": "",
        "level": "3"
      }
    }
  }
}
```

至于vulners中的字段和SecurityInfo中的含义是一样的.

## 漏洞详情网页介绍

漏洞详情网页设计的目的是,他可以脱离results.json独立展示信息给用户,方便分析漏洞的形成原因.

### vulnerability detail

是app的基本信息以及漏洞的基本信息.

### data flow

上面的target字段

### call stack

污点传播经历了哪些函数.

### code detail

详细展示了污点传播的过程. 如果`config.json5`中指定了javaSource为true,那么还会展示反编译后的函数的java代码.




