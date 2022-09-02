# Running parameter description

The configuration set by parameters and the EngineConfig file are adjustment of Appshark's parameters. Specifically, parameters are one time for the current app, while the EngineConfig is for all the apps.

## Parameters required to be specified

apkPath: the absolute path of the app to be scanned
rules: the rules applied to the scanning, which are a comma-separated list of rules

## Other default parameters

### CallBackEnhance

If it is `true`, then it will insert a rewritten version of invocation statements to related methods in anonymous classes. In this way, we can model the implicit method calls. For example,

 ``` 
  sensitiveApi.setOnClickListener(new MyListener() {
        public void onClick(View v) {
            //call
        }
    });
    // will insert a line of an invocation below
    // l.onClick(null); //l is the newly created instance of MyListener
 ```

 ### maxPointerAnalyzeTime

It is the maximum timeout for pointer analysis, in seconds. If it is too short, it may lead to FPs and FNs because some of the code is not analyzed.

### javaSource

Whether to display the source code in the final vulnerability details. The source code is decompiled from [jadx](https://github.com/skylot/jadx) tool

### maxThread

It controls the degree of parallelism when performing analyses such as pointer analysis. Its default value is CPU core number of the running machine. If OOM happens, then we can lower its value to save memory. But the runtime will be longer.

### rulePath

The folder path of the rule files: it is given in an absolute path. Its default value is `lib/rules` in the project directory. 

### sdkPath

The path of Android SDK: its default value is `tools/platforms` in the project directory. 

### toolsPath

The folder path of the 3rd party tools: its default value is `tools` in the project directory. 

### supportFragment

Whether to consider lifecycle callbacks in a Fragment class. It is similar to process lifecycle callbacks (e.g. onCreate) in an Activity class.

### logLevel

Log's output level, default is info (1):

- debug 0
- info 1
- warn 2
- error 3

### ruleMaxAnalyzer

To prevent errors in a rule: if a rule is problematic, it may match too many sources and sinks. Its default value is 5,000, which should be good for most rules. 
If you see `rule xxxx has too many rules: xxxx, dropped`, then you can consider increasing its value.

### maxPathLength

The longest path length from source to sink. Paths exceeding this length will be discarded even if they are valid.

### wholeProcessMode

whether to enable whole program analysis: false by default. The whole program analysis impacts the analysis scope.

- May increase the analysis time considerably. It makes Appshark try to analyze each statement in the app, regardless of the relationship between source and sink specified by the user.
- More FPs and TPs due to the increased scope
- The pointer analysis step will be strictly single-threaded and cannot be parallelized

#### Scenarios recommended to enable

When the app size is small and the results can be obtained within your acceptable time and memory usage

#### Scenarios recommended to disable

When the app size is large and complex. Because it is almost impossible to get the results in an acceptable time. 

#### Comparison with SliceMode, DirectMode

In a rule, no matter whether directly or indirectly, there are an analysis entry and an analysis trace depth specified. However, these two settings are ignored in wholeProcessMode
Clearly, the path finding step still uses source, sink, and sanitizer information in a rule. 

#### skipAnalyzeNonRelatedMethods

There are so many methods that can be reached from the entry method within the path length of `traceDepth`. Is this necessary? An option is to only consider those reached methods that are related to sources and sinks. 
Its default value is `false`, meaning taking all those methods into account. `True` indicates that skipping reached methods that have nothing to do with source and sink. Say,

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

f() is the analysis entry. If skipAnalyzeNonRelatedMethods is true, h() will be neglected. Otherwise, h() will be analyzed. 

#### skipPointerPropagationForLibraryMethod
Currently, our pointer analysis is context insensitive. For library methods, such as `java.util.Iterator: java.lang.Object next()`, we can ignore the pointer information propagation in some cases to save some time. The potential side effect is to have more FPs and FNs.

If the value is `true`, that is, do not propagate pointer information for library methods. We only track the pointer info defined by our predefined heuristics in the statement containing a library method call. 

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

Note that EngineConfig.json5 includes a rule below:

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
When skipPointerPropagationForLibraryMethod is enabled, append() is a library method,, so we  propagate as follows:
s1->{new StringBuffer();} // per StringBuffer s1=new StringBuffer();
s2->{new StringBuffer();,null} // per s2=s1.append("aa"); and PointerFlowRule
s3->{null}

When skipPointerPropagationForLibraryMethod is off, then we propagate as follows:
s1->{new StringBuffer();} // per StringBuffer s1=new StringBuffer();
s2->{new StringBuffer();,null} // per s2=s1.append("aa"); and PointerFlowRule
s3->{new StringBuffer();,null}