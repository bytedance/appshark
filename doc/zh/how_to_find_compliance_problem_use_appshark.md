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



# 如何使用appshark找出程序中的隐私合规问题.
 


Appshark可以对应用进行数据流分析，也可以只查找某个API的调用点，这两种功能都可以帮助你分析应用中可能存在的隐私合规风险。隐私合规相关规则的编写方式与安全漏洞规则基本一致，因此在开始之前，请先阅读 如何为Appshark撰写规则
## 隐私数据流分析
隐私数据流分析就是数据流分析的其中一种，但绝大部分时候你不需要编写entry和sanitizer，你应该更关心规则中的source和sink。    
具体来说，你可以将source指定为某个获取隐私信息的API，例如：    
```
"source": {
    "Return": [
        "<android.telephony.TelephonyManager: * getDeviceId(*)>"
    ]
}
```
这个API的return是设备唯一标识IMEI。    
同时，将sink指定为你认为会存在隐私数据泄露的方法，例如写文件：    
```
"sink": {
    "<java.io.FileOutputStream: * write(*)>": {
        "TaintCheck": [
            "p0"
        ]
    }
}
```
当你所关注的隐私数据来源并非API，而是对象的某个field时，你依然可以按照通用规则编写中field类型source的格式编写规则，例如设备序列号作为source：    
```
"source": {
    "Field": [
        "<android.os.Build: * SERIAL>"
    ]
}
```
最后，你需要使用SliceMode，可以减少分析的时间。   

 
完整的规则文件:
```json
{
  "getDeviceId": {
    "SliceMode": true,
    "traceDepth": 8,
    "desc": {
      "name": "getDeviceId",
      "category": "ComplianceInfo",
      "detail": "",
      "wiki": "",
      "complianceCategory": "PersonalDeviceInformation",
      "complianceCategoryDetail": "PersonalDeviceInformation",
      "level": "3"
    },
    "source": {
      "Return": [
        "<android.telephony.TelephonyManager: * getDeviceId(*)>"
      ],
      "Field": [
        "<android.os.Build: * SERIAL>"
      ]
    },
    "sink": {
      "<java.io.FileOutputStream: * write(*)>": {
        "TaintCheck": [
          "p0"
        ]
      }
    }
  }
}
```