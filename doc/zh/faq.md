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


# 常见问题
 

## 1. Appshark与soot的关系?
Appshark分析的对象是soot生成的jimple IR,soot 是Appshark的基座. 但是Appshark有自己独立的规则系统,以及独立实现的指针分析和污点分析算法. 

## 2. Appshark与flowdroid的关系?
Appshark使用了flowdroid对android manifest,xml文件,各种resouce文件等的解析模块,但是Appshark有自己独立的规则系统,以及独立实现的指针分析和污点分析算法. 

## 3. sliceMode 可能存在什么问题?

```java
public class SliceMode {
    public static void main(String[] args) {
      A x=new A();
      A y=x;
      f(x,y);
    }
    void f(A x,A y){
        dosource(x);
        dosink(y);
    }
    void dosource(A x){
        x.f=source();
    }
    void dosink(A y){
        sink(y.f);
    }
}
```
如果sliceMode进行分析,那么会得到分析的入口点是函数f, 那么将无法得到x,y实际上指向的是同一个object,从而无法形成从source到sink的传播路径,导致漏报.

## 4. field sensitive 
我们的分析是field sensitive的,不会混淆不同field的传播.
比如:
```java
public class FieldSensitive{
    public static void main(){
        A x=new A();
        x.f1=source();
        sink(x.f2);
    }
}
```
不会形成一条从source到sink的传播路径,因为x.f1和x.f2是不同的field.

## 5. 哪些是appshark不能解决的问题

- appshark是一个静态分析引擎,因此凡是需要运行app进行识别的,都不支持. 比如app在同意隐私政策前,调用了哪些api. 再比如把app运行起来,收集一下它调用了哪些函数等.

## 6. 运行时间远远超过预期怎么办?
appshark时间主要有以下三块组成:
1. app预处理,生成jimple
2. 指针分析
3. 漏洞查找

其中maxPointerAnalyzeTime参数只影响指针分析的时间. 其他两个步骤的时间是无法直接控制的,因此如果cpu在运行中一直维持在较低的占用率,建议增加并行线程数,
因为默认的线程数只有2,


## 7. 有不少隐私合规问题,比如超范围收集等,是否适合用appshark来解决?
静态扫描确实不能覆盖很多隐私合规场景，尤其是过度，频繁,未经用户明确同意之类的问题。 但是有不少其他问题，比如有没有，存不存在这样的问题，静态是可以解决的。

## 8. 出现OOM怎么办?
当出现这样的字眼`java.lang.OutOfMemoryError: Java heap space` 时,建议增大appshark的运行内存. 可以通过` java -Xmx32g   -jar AppShark-0.1.2.jar config.json` 来增大内存.

