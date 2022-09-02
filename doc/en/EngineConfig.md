# EngineConfig Description
EngineConfig.json5 is a more in-depth configuration of the engine. If you do not understand the exact meaning, it is recommended to keep this file unchanged.

## IgnoreList
The methods that match the keywords will be ignored during the analysis. The ignoreLise can be specified using keywords with different granularities.
- PackageName: all methods in this package will be ignored
- MethodName: all methods with this name will be neglected
- MethodSignature: methods with this signature will not be considered

## Callback
When an implemented class of an interface is created and called implicitly, insert an explicit call statement automatically. For example,
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
// insert the statement below to call explicitly
// r.run();
```

## Library

Specify packages to be considered as library. This is to reduce the analysis workload of Appshark, because it is believed that code in framework or jdk do not contain vulnerabilities.
If a package is marked as library, it will have the following impacts: 
1. Ignore library code when constructing the call graph
2. Sources and sinks can be matched for library only
3. When encountering library method calls, we will apply the propagation rules (i.e. PointerFlowRule and VariableFlowRule), instead of their implementation, to calculate pointer and data flow info between variables.  

## PointerFlowRule
**Modify the rule only when you have a strong reason**
The rule describes how to handle the pointer information in a method call when the callee method is from a library or exceeds the `traceDepth` from the entry. 
Basic principle: **if there is no matching rule, then the related points-to relationship is not considered**

Keywords in this kind of rule:
 - p*: all parameters
- @this: this pointer in a method call
- ret: the return value of the method
- p0,p1,p2: 0th,1st,2nd argument of a method
- @this.data: a dummy field representing this object's all fields
- I: input
- O: output

Like above, MethodName or MethodSig can be specified to match methods by a method name or a method signature.

An example for keySet():
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

When encountering the below code:
```java
HashMap m=new HashMap();
m.put("s1","s2");
m.put("i",new Intent());
Set s= m.keySet();
```
Variable s (i.e. the return value of keySet()) points to m's all fields. If `@this.data` points to objects `("s1","s2","i",new Intent())`, then s points to these objects as well. 


## VariableFlowRule

The rule describes how to handle the data flow information in a method call when the callee method is from a library or exceeds the `traceDepth` from the entry. 
The difference between it and PointerFlowRule is that it has default data flow relationship, including:
- InstantDefault
- InstantSelfDefault

The difference between InstantSelfDefault and InstantDefault is that the former explicitly requires the `this` pointers of caller and callee to be the same. Say,
```java
class C{
    void f(){
        g();
    }
    void g(){

    }
}
```
Since f() and g() are from the same instance, the data flow relationship is InstantSelfDefault rather than InstantDefault.

**Same as PointerFlowRule, keywords in this kind of rule:**

 - p*: all parameters
- @this: this pointer in a method call
- ret: the return value of the method
- p0,p1,p2: 0th,1st,2nd argument of a method
- @this.data: a dummy field representing this object's all fields
- I: input
- O: output

Here is an example.
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
If `@this.data` points to objects `("s1","s2","i",new Intent())`, then data in the HashMap will flow from `("s1","s2","i",new Intent())` to obj, and then flow from m to obj. 

In other words, if `new HashMap()` is a tainted source, the obj will be tainted. If "s1" is a tainted source, then obj will also be tainted.
