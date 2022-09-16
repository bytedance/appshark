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


# 运行参数说明
 

运行参数配置和EngineConfig都是对appshark的参数调整,但是前者针对的是本次app的扫描,而后者相对稳定,针对的是所有的App.

## 必须指定的参数

apkPath: 要扫描的app的绝对路径.
rules: 扫描使用的规则,以逗号分隔的一系列规则列表.

## 其他缺省参数

### CallBackEnhance

CallBackEnhance, 如果该参数为true,那么默认会把所有的匿名类重写的函数直接进行调用. 比如:

 ``` 
  sensitiveApi.setOnClickListener(new MyListener() {
        public void onClick(View v) {
            //call
        }
    });
    //会在下面插入一行
   // l.onClick(null); //其中l是刚刚创建的MyListener
 ```

### maxPointerAnalyzeTime

指针分析的超时时间,以秒为单位. 如果该时间较短,可能会导致因为部分代码没有分析到,而导致误报和漏报.

### javaSource

是否在最终的漏洞详情中展示源码. 该源码是通过jadx反编译得到.

### maxThread

控制内部进行指针分析等操作时的并行度,默认数量为2. 如果发生了OOM,可以通过降低该数值来节省内存,但是这会导致分析时间的增加. 如果一直不能分析结束,
可以通过增加线程数来节省时间,可以将线程数调整为CPU核数.

### rulePath

规则文件所在的文件夹,请以绝对路径给出. 默认是当前工作目录下的`lib/rules`.

### sdkPath

安卓框架所在目录,默认是当前工作目录下的`tools/platforms`

### toolsPath

jadx,platforms所在的目录,默认为当前工作目录下的`tools`.

### supportFragment

是否对处理Fragment的lifeCycle函数. 类似于处理Activity的onCreate等函数.

### logLevel

日志输出级别,默认为info (1):

- debug 0
- info 1
- warn 2
- error 3

### ruleMaxAnalyzer

防止出错用,如果一个规则写的有问题,可能会导致匹配到非常多的source和sink. 这个数值默认5000,绝大多数情况下都应该满足要求,
如果你在分析时,碰到`rule xxxx has too many rules: xxxx, dropped`,可以考虑增加这个数值.

### maxPathLength

source到sink的最长路径,超过这个长度的路径,就算是有效也会被丢弃.

### wholeProcessMode

是否进行全程序分析,默认为false. 全行程分析主要是影响分析的范围.
开启全程序的影响

- 可能会大幅加大分析时间. 该选项会导致Appshark尽可能的分析app中的每一条指令,而不关心他与用户指定的source,sink的关系.
- 因为分析范围的增加,可能会带来更多的误报,也可能会带来更多的发现.
- 指针分析过程将会是严格的单线程,无法并行

#### 什么时候建议开启该选项

如果你分析的app比较小,能够在你可接受的时间空间之内取得结果,那么建议开启此选项.

#### 什么时候不应该开启该选项

如果你的app非常大, 代码非常复杂,那么你不应该开启次选项. 因为他几乎不可能在你可接受的时间之内分析出结果.

#### 与SliceMode,DirectMode的关系

在具体的Rule中,无论是通过直接还是间接方式,都会有一个分析入口以及分析的深度(traceDepth),但是一旦开启了全程序分析,那么这些入口和深度都将会被视若无睹.
当然指针分析完成之后的路径查找,仍然会使用相关Rule中的source,sink以及sanitizer.

#### skipAnalyzeNonRelatedMethods

从分析入口开始,在指定的`traceDepth`下,可以抵达很多函数,那么是否有必要对所有这些函数都进行分析呢? 有一个选择是,只对和source,sink相关的函数进行分析.
默认为false,即对这些所有函数进行分析,为true,则跳过那些明显与source,sink无关的函数.
比如:

``` 
Class C{
    void f(){
        Object o=source();
        g(o);
        h();
    }
    void g(Object o){
        sink(o);
    }
    void h(){

    }
}
```

如果f为分析的入口,skipAnalyzeNonRelatedMethods为true的时候,会跳过对h的分析,就像`h()`调用不存在一样. 否则会对h进行分析.

#### skipPointerPropagationForLibraryMethod

目前的指针分析过程采用的是上下文不明感分析(context insensitive),对于像`java.util.Iterator: java.lang.Object next()`这样的函数,就会大量普遍存在.
实际上普通地方的next函数的this指针以及返回值都是没有关系的. 因此在这种场景下,如果避免做指针的propagation,可以节省不少时间. 当然不propagation有可能会带来误报和漏报.

该值默认为true,即不对library中的method做指针的propagation,只按照规则做一次指向计算.

```java 
Class C{
    void f(){
            StringBuffer s1=new StringBuffer();
            StringBuffer s2=null;
            StringBuffer s3=s2;
             s2=s1.append("aa");
            String s=s3.toString();
      }
}
```
注意EngineConfig.json5中有这样的规则:
```json5
{
  PointerFlowRule: {
    "MethodSignature": {
      "<java.lang.StringBuffer: java.lang.StringBuffer append(java.lang.String)>": {
        "@this->ret": {
          "I": [
            "@this"
          ],
          "O": [
            "ret"
          ]
        }
      },
    },
  }
}
```
如果skipPointerPropagationForLibraryMethod为true,append是library中的method,所以在指针传播过程中,会根据规则,得到

s1->{new StringBuffer();} //根据    StringBuffer s1=new StringBuffer();

s2->{new StringBuffer();,null} //根据s2=s1.append("aa"); 以及PointerFlowRule

s3->{null}

如果skipPointerPropagationForLibraryMethod为false,那么指针指向关系将是:

s1->{new StringBuffer();} //根据    StringBuffer s1=new StringBuffer();

s2->{new StringBuffer();,null} //根据s2=s1.append("aa"); 以及PointerFlowRule

s3->{new StringBuffer();,null}






