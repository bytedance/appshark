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


# EngineConfig 说明
 
EngineConfig.json5 是对引擎更深入的配置,如果不理解其准确含义,建议不要修改这个文件. 

## IgnoreList
被这里命中的函数在分析时,将会被忽略. 指定函数的规则有三种形式:
- PackageName 整个包下面的函数都会被忽略
- MethodName 以函数名字进行匹配
- MethodSignature 以函数签名进行匹配.

## Callback
当创建碰到指定的类被创建时,自动调用相关函数. 比如
```json
 "java.lang.Runnable": [
        "void run()"
      ]
```
```java
Runnable   r=new Runnable(){
    @Override
    public void run() {
        //do something
    }
};
//相当于自动在这条语句下面添加了一条
//r.run();
```

## Library

指定的package,将会被认为是library,主要用于降低Appshark分析的工作量,因为通常认为framework,jdk等代码中不会存在漏洞. 
如果一个package被标记为Library,主要有一下几点需要注意:
1. 构建call graph的时候会自动忽略library的代码
2. source,sink中会有对library的限制
3. library的代码在分析的时候,会通过PointerFlowRule和VariableFlowRule计算指针以及数据流传播规则,而不是根据其具体实现代码.


## PointerFlowRule
**如果不确定要不要修改该配置,那么就不要修改,除非有明确的证据**
该配置主要是解决library代码以及超出规则中指定的`traceDepth`时,如何处理相关的函数调用的指针指向关系.
PointerFlowRule 一个基本原则是: **如果没有匹配的规则,那么就不处理相关的指向关系**.

该规则中的关键字:
- p* 所有参数
- @this 函数调用时的this指针
- ret 函数的返回值
- p0,p1,p2 函数的参数0,1,2,...
- @this.data 一个虚拟字段,代表this对象的所有字段.
- I 表示输入
- O 表示输出

MethodName 是按照函数名来匹配函数,MethodSig是按照函数签名来匹配函数. 

以keySet规则为例来说明:
```json
      "<java.util.Map: java.lang.Object keySet()>": {
        "@this.data->ret": {
          "I": [
            "@this.data"
          ],
          "O": [
            "ret"
          ]
        }
      }
```
碰到如下代码:
```java
HashMap m=new HashMap();
m.put("s1","s2");
m.put("i",new Intent());
Set s= m.keySet();
```
变量s(也就是keySet的返回值)将指向m中的所有字段. 如果此时`@this.data`指向了`["s1","s2","i",new Intent()]`这些object,那么s也会指向这些object.
但是s并不会指向`new HashMap()` 这个对象,因为没有从this到ret的关系.

## VariableFlowRule

该配置主要是解决library代码以及超出规则中指定的`traceDepth`时,如何处理相关的函数调用的数据流向关系.
它与PointerFlowRule在处理时的一个重要区别是,它有缺省的数据流向关系,也就是:
- InstantDefault
- InstantSelfDefault

InstantSelfDefault和InstantDefault的区别是,前者明确要求caller和callee的this指针是相同的. 比如:
```java
class C{
    void f(){
        g();
    }
    void g(){

    }
}
```
那么在分析f中对g的调用时,数据流向关系按照InstantSelfDefault而不是InstantDefault.

**VariableFlowRule的关键字和PointerFlowRule是一样的**

- p* 所有参数
- @this 函数调用时的this指针
- ret 函数的返回值
- p0,p1,p2 函数的参数0,1,2,...
- @this.data 一个虚拟字段,代表this对象的所有字段.
- I 表示输入
- O 表示输出

以下面规则为例来解释:
```json
"<java.util.Map: java.lang.Object remove(java.lang.Object)>": {
"@this.data->ret": {
    "I": [
    "@this.data"
    ],
    "O": [
    "ret"
    ]
},
"@this->ret": {
    "I": [
    "@this"
    ],
    "O": [
    "ret"
    ]
}
}
```

```java
HashMap m=new HashMap();
m.put("s1","s2");
m.put("i",new Intent());
Object obj= m.remove("i3");
```
如果此时`@this.data`指向了`["s1","s2","i",new Intent()]`这些object,那么HashMap数据将会从`["s1","s2","i",new Intent()]`流向m,进而会从m流向obj. 

也就是,如果`new HashMap()`是污点,那么obj将会被污染. 如果"s1"是污点,那么obj也会被污染.

