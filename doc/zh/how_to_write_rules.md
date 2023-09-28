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


# 如何为Appshark撰写规则


使用Appshark进行数据流分析,最重要的就是明确告诉Appshark你关心的分析入口,source,sink以及sanitizer. 根据source的特殊性,将其分类为:

- ConstStringMode 支持常量字符串作为source
- ConstNumberMode 支持常量整数作为source
- SliceMode和DirectMode 其他类型的source

## 背景知识

Appshark分析的对象是经过SSA处理的jimple指令,因此在指定source/sink的时候,引用的函数以及field签名必须符合jimple格式.

### jimple函数签名

`<android.content.Intent: android.content.Intent  parseUri(java.lang.String,int)>`
这是一个通用的Java函数签名,包含了类名,函数名,函数返回类型,参数类型列表. 在指定source,sink的过程中,每个部分都可以用*来模糊匹配.
比如`<*: android.content.Intent  parseUri(java.lang.String,int)>` 匹配所有类中,函数名字为`parseUri`
,返回类型是Intent以及参数列表为`java.lang.String,int`的函数.

### jimple field签名

`<com.security.TestClass: android.content.Intent  fieldName>`
这是一个通用的Java 对象的field签名,这个field的类名是`com.security.TestClass`,类型是`android.content.Intent`,field的名字是`fieldName`.
**field签名不支持模糊匹配指定,必须准确给出**

## 一般规则的撰写

一般规则包含四个部分,分别是:1. 分析的入口 2. source 3. sink 4. sanitizer.

### 分析入口的指定

分析的入口一般是一个函数. 比如

```json
"entry": {
"methods": [
"<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>"
]
}
```

entry只有在`DirectMode`下需要明确指定,其他三个模式下,都无需明确指明分析入口. 如果你不知道分析入口是什么,说明你不应该使用`DirectMode`.

### 一般source的指定
**需要说明的是,appshark内部真正的source点会是具体的变量,因此无论哪种写法,都会转换成一个具体的变量.**
source可以有很多种类型,分别是:

- 常量字符串,注意这与`ConstStringMode`是没关系的
- 函数返回值
- 函数的某个参数
- 对象的某个field
- 某个对象的创建
  

下面分别举例介绍这五种情况.

#### 常量字符串

```json
"source": {
"ConstString": ["path1"]
}
```

那么:

```java
String s="path1";
f(12,"path1");
```

s将成为source.
函数f的参数1将成为source.

#### 函数的返回值

这种一种最常见的source形式,比如:

```java
"source": {
  "Return": [
    "<java.util.zip.ZipEntry: java.lang.String getName()>"
  ]
}
```
也就是getName的返回值将会是source.
那么:
```java
ZipEntry e=getEntry();
String name=e.getName();
```
name将成为source点.

#### 某对象的field
比如:
```json
 "source": {
            "Field": [
                "<android.provider.CalendarContract: android.net.Uri CONTENT_URI>",
            ]
  }
```
那么:
```java
Uri uri=CalendarContract.CONTENT_URI;
```
uri将会成为source点. 
**注意不区分该field是静态field还是非静态field**

#### 某个函数的参数
函数参数作为source一般在重写系统类的情况,
比如:
```json
    "source": {
  "Param": {
    "<android.webkit.WebViewClient: android.webkit.WebResourceResponse shouldInterceptRequest(android.webkit.WebView,android.webkit.WebResourceRequest)>": [
      "p1"
    ]
  }
}
```
首先注意,p0是第一个参数,p1是第二个参数,这里类型为WebResourceRequest才是source. 

#### 某个对象的创建
这个规则非常特殊,一般不会用到. 
比如:
```json
 "source": {
  "NewInstance": ["android.content.Intent"]
 }
```
那么:
```java
android.content.Intent i=new android.content.Intent();
```
这时候变量i将成为source点.

### 一般sink的指定
目前sink点只能是函数的周边,可以是:
- this指针 @this
- 函数的某个参数 p0,p1,p2
- 函数的所有参数 p*
- 函数的返回值 return

#### sink
需要强调的是,**所有的sink都会在内部转换成具体的变量**.
sink的指定相对于source的指定要简单许多,种类也比较单一.
例如:
```json
    "sink": {
      "<com.security.FileWrapper: * <init>(*)>": {
        "LibraryOnly":true,
        "TaintCheck": [
          "p*"
        ]
      },
      "<java.io.FileOutputStream: * <init>(*)>": {
        "TaintCheck": [
          "p*","@this"
        ]
      },
      "<android.app.*: int onStartCommand(*)>": {
        "TaintCheck": [
          "return"
        ]
      }
    }
```
 那么:
 ```java
String path;
File f=new File(path);
FileOutputStream fileOutputStream=new FileOutputStream(f);
 ```
 这里面的f,fileOutputStream都会是sink点. appshark会检查能否找到从source到这些变量的一个污点传播路径.

sink还有一个可配置的选项就是`LibraryOnly`,默认值为false,如果设置为true,那么就要求匹配到的函数签名必须是`EngineConfig.json5`中指定的Library.
以上面例子为例,如果在`EngineConfig.json5`中指定`com.security`为Library,那么path就是sink点. 
否则如果没有在`EngineConfig.json5`中指定`com.security`为Library,那么path就不是sink点. 

### sanitizer的指定

sanitizer目的是消除误报. 虽然发现了一条从source到sink的完整传播路径,但是因为已经对source做了严格的校验,所以这并不是一条有效的路径.
下面以unzipSlip规则为例来介绍一下sanitizer的原理.  
zip slip漏洞的原理可以参考[Directory traversal attack](https://en.wikipedia.org/wiki/Directory_traversal_attack). 主要是在解压zip文件的时候,没有检查文件名中是否包含"../",导致如果zip文件外部可控的话,可能会导致任意文件覆盖问题.

首先给出完整的规则:
```json
{
  "unZipSlip": {
    "SliceMode": true,
    "traceDepth": 8,
    "desc": {
      "name": "unZipSlip",
      "category": "FileRisk",
      "detail": "ZIP Slip is a highly critical security vulnerability aimed at these kinds of applications. ZIP Slip makes your application vulnerable to Path traversal attack and Sensitive data exposure.",
      "wiki": "",
      "possibility": "4",
      "model": "middle"
    },
    "source": {
      "Return": [
        "<java.util.zip.ZipEntry: java.lang.String getName()>"
      ]
    },
    "sanitizer": {
      "getCanonicalPath": {
        "<java.io.File: java.lang.String getCanonicalPath()>": {
          "TaintCheck": [
            "@this"
          ]
        }
      },
      "containsDotdot": {
        "<java.lang.String: boolean contains(java.lang.CharSequence)>": {
          "TaintCheck": [
            "@this"
          ],
          "p0": [
            "..*"
          ]
        }
      },
      "indexDotdot": {
        "<java.lang.String: boolean indexOf(java.lang.String)>": {
          "TaintCheck": [
            "@this"
          ],
          "p0": [
            "..*"
          ]
        }
      }
    },
    "sink": {
      "<java.io.FileWriter: * <init>(*)>": {
        "TaintCheck": [
          "p*"
        ]
      },
      "<java.io.FileOutputStream: * <init>(*)>": {
        "TaintCheck": [
          "p*",
          "@this"
        ]
      }
    }
  }
}
```

source和sink就不展开说了,上面刚刚介绍过.

重点说一下sanitizer,因为它的设计不是那么容易理解.

#### 顶层规则是或的关系
sanitizer分别包含了三个子key: 
- getCanonicalPath
- containsDotdot
- indexDotdot
这三个规则是或的关系.  根据规则,我们会找到N个 source,M个sink.  那么理论上就会存在N*M条路径.对于其中的任意一条路径,如果它满足了这三条规则中的任意一条,就会被sanitize掉.

#### 二层规则之间是与的关系
由于这个例子中,二层规则都只有单独一条,所以这里造一个规则来演示.
```json
      "containsDotdot": {
        "<java.lang.String: boolean contains(java.lang.CharSequence)>": {
          "TaintCheck": [
            "@this"
          ],
          "p0": [
            "..*"
          ]
        },
        "<java.io.File: * init(java.lang.String)>": {
          "TaintCheck": [
            "@this"
          ]
        }
      }
```
如果某条路径同时满足对`<java.lang.String: boolean contains(java.lang.CharSequence)>`和`<java.io.File: * init(java.lang.String)>`这两个函数的限制,那么这条路径就会被sanitize掉.

#### 具体规则的含义
再次强调,**appshark分析的是污点在变量之间的传递关系,所以无论是source,还是sink,还是sanitizer描述的具体粒度都是变量.**
以containsDotdot为例:
```json
"containsDotdot": {
        "<java.lang.String: boolean contains(java.lang.CharSequence)>": {
          "TaintCheck": [
            "@this"
          ],
          "p0": [
            "..*"
          ]
        }
}
```
它的限制有两个:
1. TaintCheck
从source出发,传播到的所有变量中,是否污染到了`<java.lang.String: boolean contains(java.lang.CharSequence)>`这个函数的this指针.
比如:
```java
if(path.contains("../")){
  return false
}
```
那么这里的path就是contains的this指针,

2. 参数取值的限制
`"p0":["..*"]`的含义是: 常量字符串`..*`要能污染到contains的参数0.
3. NotTaint
这个和TaintCheck格式一样,意思相反,要求函数的这些地方不能被source污染到.

这两个条件之间也是与的关系,因此:
```java
String path=zipEntry.getName();
if(path.contains("../")){
  return false
}
File file=new File(path);
FileOutputStream fileOutputStream=new FileOutputStream(file);
```
满足我们的sanitizer,从source(path)到sink(file)的这条传播路径就会被sanitize掉.

反之:
下面的例子中,就不能被sanitize掉.

```java
String path=zipEntry.getName();
String s=anotherFunction();
if(s.contains("../")){
  return false;
}
if(path.contains("root")){
  return false;
}
File file=new File(path);
FileOutputStream fileOutputStream=new FileOutputStream(file);
```
这个例子中`s.contains("../")`满足了对p0的检验,但是没有满足TaintCheck的检验. 而`path.contains("root")`满足了对TaintCheck的检验,但是没有满足对p0的检验. 所以这条传播路径是有效的.


#### sanitizer总结
sanitizer针对的是,已经找到了一条从source到sink的路径,再根据source污染到的所有变量进行过滤,如果满足条件就删掉这条路径,否则保留.

## 四种mode的特殊性

### DirectMode的特殊性
它需要明确指明分析的入口,比如:
```json
    "entry": {
      "methods": [
        "<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>"
      ]
    }
```
那么这条规则的分析入口就是`UnZipFolder`这个函数.

这里还可以是一些虚拟入口,但是目的都是一样的,比如:
```json
    "entry": {
      "ExportedCompos": true
    }
```
这里的意思是,每个安卓的导出组件都是分析入口. 比如Activity的onCreate,onDestroy等等都是分析的入口. 这些入口有appshark根据manifest文件的解析得到,而不是写死,相对灵活一点.  当然你也可以针对具体的app,自行分析manifest文件,然后把每个导出的组件中的函数写到规则中,这样效果是一样的.

这里还有一个关键特性就是`traceDepth`,这里指的是从分析入口函数开始,分析多少层函数调用为止. 如果调用层级超过这个深度,会被忽略.
### SliceMode的特殊性
SliceMode和DirectMode的区别是它的分析入口不是固定的,而是根据具体的source,sink计算得到的. 
这个mode的提出针对的是,在某些场景下,就没有固定的分析入口. 或者从指定的入口开始到我们想要分析的那部分代码之间距离太远,导致不能在有效的时间内取得分析结果.

怎么根据source和sink计算分析入口,主要有两种情况:
- source为某个函数的参数
- 其他形式的source
#### source为某个函数参数
以下面的例子来说明:
```json
    "source": {
  "Param": {
    "<android.webkit.WebViewClient: android.webkit.WebResourceResponse shouldInterceptRequest(android.webkit.WebView,android.webkit.WebResourceRequest)>": [
      "p1"
    ]
  }
}
```
首先shouldInterceptRequest针对是WebViewClient的子类而言的,因为`android.webkit.WebViewClient`是安卓的framework,我们并不会直接去分享framework的代码. 
这里的source是shouldInterceptRequest的p1,也就是`WebResourceRequest`这个参数. 如果我们override了`shouldInterceptRequest`这个函数,那么将会从这个函数出发,找出它所有的显式或者隐式的被调函数,看看里面有没有包含sink点的函数. 如果有就将这个override的`shouldInterceptRequest`函数作为分析入口.

这里有一个规则的`traceDepth`,指的是从shouldInterceptRequest出发,查找的函数层数. 

#### 其他形式的source
比如:
```json
"source": {
  "Return": [
    "<java.util.zip.ZipEntry: java.lang.String getName()>"
  ]
}
```
意思是从`source`点往下搜索`traceDepth`层,从`sink`点往上搜索搜索`traceDepth`层,找到它们最近交汇的函数作为分析入口.



### ConstStringMode
它之所以特殊,因为app中的常量字符串太多可能非常多,所以其分析的入口不受`traceDepth`的约束,它分析的入口就是指定的常量字符串所在的函数.
比如:
 ```java
void f(){
  String s="constant_string"
  g(s);
}
 ```
 如果s是满足我们条件的常量字符串,那么f就是分析入口.
 限制常量字符串的条件有:
 - constLen 长度必须是这个长度的倍数
 - minLen 长度不能小于这个长度
 - targetStringArr 形式上满足这个数组中的任意一个,比如 `"targetStringArr": ["AES","DES","*ECB*"]`


 ### ConstNumberMode
 它与ConstStringMode类似,其分析入口也是这个常量数值所在的函数. 

对于常量数值的限制,只有`targetNumberArr`,它表示只关心这个数组里面的数值.
比如:
```json
    "ConstNumberMode": true,
    "targetNumberArr": [
      16
    ]
```



## 规则的高级特性

### TaintTweak

**注意这部分内容只针对非全程序分析模式。**

在非全程序分析的模式下,如果我们想阻断污点的传播,或者我们自己知道污点怎么传播,默认的规则不能满足我们的要求,可以为单独每个规则指定污点传播关系.

比如

```json
{
      "TaintTweak": {
      "MethodSignature": {
        "<android.content.Intent: void <init>(java.lang.String,android.net.Uri,android.content.Context,java.lang.Class)>": {},
      },
      "MethodName": {
        "putCharSequenceArrayListExtra": {}
      }
    }
}
```



这部分规则的配置方式和`EngineConfig.json5`中的`VariableFlowRule`的含义是类似的,只不过`VariableFlowRule`针对的是所有的规则,而TaintTweak针对的是当前这一条规则.



那么上面的规则的含义就是:

- 函数`<android.content.Intent: void <init>(java.lang.String,android.net.Uri,android.content.Context,java.lang.Class)>` 将不做任何污点传播. 
- 名为`putCharSequenceArrayListExtra`的函数也不会做任何污点传播.



## APIMode

APIMode和前面的几种mode都不一样,他并不是一个数据流分析的规则,而是一个简单的查找指定api的规则, 比如下面的一个规则(来自 [camile.json](https://github.com/bytedance/appshark/blob/main/config/rules/camile.json)).

```json
{
  "获取蓝牙设备信息": {
    "desc": {
      "category": "camille",
      "detail": "获取蓝牙设备信息",
      "name": "获取蓝牙设备信息",
      "complianceCategory": "ComplianceInfo"
    },
    "sink": {
      "<android.bluetooth.BluetoothAdapter: * getName(*)>": {
      },
      "<android.bluetooth.BluetoothDevice: * getAddress(*)>": {
      },
      "<android.bluetooth.BluetoothDevice: * getName(*)>": {
      }
    },
    "APIMode": true
  }
}
```

这个规则会在整个app中检测,是否存在android.bluetooth.BluetoothAdapter.getName等三个函数的调用,并给出具体的调用位置.


## 适用于DirectMode和SliceMode的一些高级规则


### PrimTypeAsTaint
指针分析完成后,在查找从source到sink的传播链路时,默认是不会将基本类型作为污点传播的,比如:
```java
int a=Source.length();
```
如果默认规则,认为a不会被source污染,而如果PrimTypeAsTaint为true,则认为a会被source污染.

### PolymorphismBackTrace
在查找source和sink的汇聚点作为分析入口时,默认是不考虑多态的. 如果需要考虑多态,那么需要将这个选项设置为true.
举例来说:
```java 
 static abstract class A {
        protected Activity activity;
        protected Intent intent;

        public abstract void setResult();

        A(Intent intent, Activity activity) {
            this.intent = intent;
            this.activity = activity;
        }
}

class B extends A {
 B(Intent intent, Activity activity) {
  super(intent, activity);
 }

 @Override
 public void setResult() {
  this.activity.setResult(PointerIconCompat.TYPE_CONTEXT_MENU, this.intent);
 }
}


class C extends A {
 C(Intent intent, Activity activity) {
  super(intent, activity);
 }

 @Override
 public void setResult() {
 }
}

public void f(){
 A b = new B(getIntent(), this);
 b.setResult();
}
```

如果source是getIntent的返回值,sink是Activity.setResult. 当使用PolymorphismBackTrace的默认值,即false的时候,那么f并不会被认为是一个漏洞,因为在B.setResult中,没有使用到source,但是如果将PolymorphismBackTrace设置为true,那么f就会被认为是一个漏洞,因为在B.setResult中,使用到了source,而B.setResult是在A.setResult中被调用的,而A.setResult是在B的构造函数中被调用的,而B的构造函数是在f中被调用的,所以f就会被认为间接调用了`Activity.setResult`. 只有当PolymorphismBackTrace为true的时候,appshark才会认为f间接调用了Activity.setResult,从而将f作为分析入口.


