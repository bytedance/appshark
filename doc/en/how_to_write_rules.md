# How to write a rule for Appshark

When using Appshark to scan apps, it is important to clearly tell Appshark the info you care about: the analysis entry methods, sources, sinks, and sanitizers. We divide sources into the following categories:

- ConstStringMode: mark string literals as source
- ConstNumberMode: mark number literals as source
- SliceMode and DirectMode: mark other source types

## Background

The input to Appshark is Jimple statements in SSA form. Therefore, the signatures of methods and fields specified as source/sink must be in Jimple format.

### Jimple method signature

`<android.content.Intent: android.content.Intent  parseUri(java.lang.String,int)>`
This is a generic Java method signature, including a class name, a method name, a method return type, and a parameter type list. When specifying source and sink, each part can be specified as * to do fuzzy matching. 
For example, `<*: android.content.Intent  parseUri(java.lang.String,int)>` matches methods with a name `parseUri`, a return type `android.content.Intent`, and a parameter type list `java.lang.String,int` in any class.

### Jimple field signature

`<com.security.TestClass: android.content.Intent  fieldName>`
This is a generic Java field signature of an object. Its owner class is `com.security.TestClass`. Its type is `android.content.Intent`. Its name is `fieldName`.
**Field signature does not support fuzzy matching**

## Writing general rules

The general rule consists of four parts, namely: 1) the entry of the analysis, 2) the source, 3) the sink, and 4) the sanitizer.

### Specifying the analysis entry 

The entry of the analysis is generally a method. For example,

```json
"entry": {
"methods": [
"<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>"
]
}
```

The entry only needs to be specified in the `DirectMode`. In the other three modes, there is no need to specify the analysis entry. If you don't know what the analysis entry is, you should not use the `DirectMode`.

### General source specification
**It is worth noting that the real source in Appshark is specific variables, so no matter which way the source is written in, it will be converted into specific variables.**
The source can have many types, namely:

- Constant string (note that this has nothing to do with `ConstStringMode`)
- The method return value
- A parameter of the function
- A field of an object
- Creation of an object


Five examples are described below.

#### Constant string

``json
"source": {
"ConstString": ["path1"]
}
```

In the code:

```java
String s="path1";
f(12,"path1");
```

S is the source.
Parameter 1 of method f is also the source.

#### Method return value

This is one of the most common source forms, such as:

```java
"source": {
  "Return": [
    "<java.util.zip.ZipEntry: java.lang.String getName()>"
  ]
}
```
It denotes that the return value of getName is the source.
In the code:
```java
ZipEntry e=getEntry();
String name=e.getName();
```
The variable `name` is the source.

#### A field of an object
For example,
```json
 "source": {
            "Field": [
                "<android.provider.CalendarContract: android.net.Uri CONTENT_URI>",
            ]
  }
```
In the code:
```java
Uri uri=CalendarContract.CONTENT_URI;
```
Variable is the source.
**Note that it does not distinguish whether the field is static or non-static**

#### Parameters of a method
Method parameters are generally used as the source in the case of rewriting system classes.
For example,
```json
    "source": {
  "Param": {
    "<android.webkit.WebViewClient: android.webkit.WebResourceResponse shouldInterceptRequest(android.webkit.WebView,android.webkit.WebResourceRequest)>": [
      "p1"
    ]
  }
}
```
First of all, note that p0 is the first parameter, p1 is the second parameter. The parameter with the type of WebResourceRequest is the source.

### Creation of an object
This rule is very special and is generally not used.
For example,
```json
 "source": {
  "NewInstance": ["android.content.Intent"]
 }
```
In the code,
```java
android.content.Intent i=new android.content.Intent();
```
Variable i is the source.

### General sink specification
At present, the sink can only be the parameter(s) or the base object of a method, which can be:
- this pointer: @this
- some parameter of a method: p0,p1,p2 
- all parameters of a method: p*

#### Sink
Note that **all sinks will be converted to specific variables internally**.
The specification of the sink is much simpler than that of the source, and the types are relatively simple.
For example,
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
      }
    }
```
In the code,
 ```java
String path;
File f=new File(path);
FileOutputStream fileOutputStream=new FileOutputStream(f);
 ```
Variables f and fileOutputStream are sinks. Appshark checks whether it can find a taint propagation path from the source to these variables.

Another configurable option for a sink is `LibraryOnly`. Its default value is false. If it is true, then the matching method signature must be the Library specified in the `EngineConfig.json5` file.
Taking the above as an example, if `com.security` is specified as Library in the `EngineConfig.json5` file, then the variable path is a sink.
Otherwise, the variable path is not a sink.

### Sanitizer specification

The purpose of sanitizer is to eliminate false positives. Although a complete propagation path from source to sink has been found, it can be invalid because the source has been strictly checked or filtered.
Let's take the unzipSlip rule as an example to introduce the principle of sanitizer.
The principle of the zip slip vulnerability can refer to [Directory traversal attack](https://en.wikipedia.org/wiki/Directory_traversal_attack). Mainly when decompressing a zip file, it does not check whether the file name contains "../", As a result, if the zip file is externally controllable, it may cause arbitrary file overwriting problems.

First, give the complete rule:
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

We omit the discussion of sources and sinks, since we just introduced them above. We focus on explaining the sanitizer.

#### The top-level rule is an OR relationship
The sanitizer contains three subkeys:
- getCanonicalPath
- containsDotdot
- indexDotdot
These three subkeys/rules work in an OR relationship. According to the rules, we may find N sources and M sinks. Then theoretically there will be N*M paths. For each of these paths, if it satisfies any of the three rules, then it will be sanitized.

#### The relationship between the second-level rules is AND
Since there is only one second-level rule in this example, we create a rule for illustration.
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
If a path satisfies the two rules `<java.lang.String: boolean contains(java.lang.CharSequence)>` and `<java.io.File: * init(java.lang.String)>`, then this path will be sanitized.

#### Meaning of specific rules
Again, **Appshark analyzes the taint propagation relationship between variables, so source, sink, and sanitizer are described at the variable level.**
Take containsDotdot as an example:
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
It has two requirements:
1. TaintCheck
Starting from the source, check whether the `this` pointer of the function `<java.lang.String: boolean contains(java.lang.CharSequence)>` is tainted among all the variables reached it.
For example,
```java
if(path.contains("../")){
  return false
}
```
The path variable is the `this` pointer of the method `contains`.

2. The restriction on parameter values
The meaning of `"p0":["..*"]` is: The constant string `..*` must be able to taint the parameter 0 of `contains` method.
3. NotTaint
This is the same as the TaintCheck format, the meaning is the opposite. It is required that these parameters and the base object of the method cannot be tainted by the source.

An AND relationship exists between these two requirements, so:
```java
String path=zipEntry.getName();
if(path.contains("../")){
  return false
}
File file=new File(path);
FileOutputStream fileOutputStream=new FileOutputStream(file);
```
The path from variable `path` to variable `file` meets the rules, and thus is sanitized.

On the contrary, a path in the below example cannot be sanitized.

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
`s.contains("../")` meets the requirement check for p0, but not for TaintCheck. And `path.contains("root")` passes the requirement check for TaintCheck, but not for p0. So this propagation path is valid.


#### Sanitizer summary
Sanitizer is aimed at finding a path from source to sink, and then filtering it according to variables tainted by source. If the conditions are met, this path is removed, otherwise, it is retained.

## The particularity of the four modes

### Specificity of DirectMode
It needs to specify the entry of the analysis, such as 
```json
    "entry": {
      "methods": [
        "<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>"
      ]
    }
```
The analysis entry for this rule is the `UnZipFolder` method.

There can also be some dummy entries, but the purpose is the same, such as 
```json
    "entry": {
      "ExportedCompos": true
    }
```
Each Android exported component is an analysis entry. For example, Activity's onCreate, onDestroy, etc. are all analysis entries. These entries are obtained by Appshark based on the parsing of the manifest file. They are not hard-coded, thus relatively flexible. Of course, for a specific app, you can analyze the manifest file manually, and then write the methods in each exported component into the rules to achieve the same effect.

Another key field is `traceDepth`, which refers to how many layers of method calls are analyzed from the entry function. If the invocation level exceeds this depth, it will be ignored.

### Specificity of SliceMode
The difference between SliceMode and DirectMode is that SliceMode's analysis entry is not fixed, but calculated according to the concrete source and sink.
The purpose of this mode is to deal with some scenarios: there is no fixed analysis entry; or the distance from the specified entry to the part of the code we want to analyze is too far, so it cannot be obtained the results in an acceptable time.

How to calculate and analyze the entry according to source and sink, there are two main cases:
- Source is a parameter of a method
- Other forms of source
#### Source is a function parameter
Illustrate with the following example:
```json
    "source": {
  "Param": {
    "<android.webkit.WebViewClient: android.webkit.WebResourceResponse shouldInterceptRequest(android.webkit.WebView,android.webkit.WebResourceRequest)>": [
      "p1"
    ]
  }
}
```
First, `shouldInterceptRequest` is a rule for a subclass of WebViewClient, because `android.webkit.WebViewClient` is an Android framework, we will not share the code of the framework directly.
The source here is the `p1` of `shouldInterceptRequest`, which is the parameter of `WebResourceRequest`. If we override the method `shouldInterceptRequest`, then we will start from this method, find all it's explicitly or implicitly called functions, and check whether there is a method containing sink. If so, we use the overridden `shouldInterceptRequest` method as the analysis entry.

There is a field `traceDepth` here, which refers to the number of method call layers tracked from `shouldInterceptRequest`.

#### Other forms of source
Say,
```json
"source": {
  "Return": [
    "<java.util.zip.ZipEntry: java.lang.String getName()>"
  ]
}
```
It means that search downward from the `source` within the `traceDepth` layers, search upward from the `sink` within the `traceDepth` layers, and identify the method which is the first intersection of both directions as the analysis entry.


### ConstStringMode
It is special because there are too many constant strings in an app, so the entry of its analysis is not constrained by `traceDepth`, and the entry of its analysis is the method where the specified constant string locates.
Say,
```java
void f(){
  String s="constant_string"
  g(s);
}
 ```
 If `s` is a constant string satisfying our condition, then f() is the analysis entry.
The conditions for a constant string are:
- `constLen`: its length must be a multiple of this length
- `minLen`: its length cannot be less than this length
- `targetStringArr`: it formally satisfies any of these arrays, such as `"targetStringArr": ["AES","DES","*ECB*"]`


### ConstNumberMode
It is similar to ConstStringMode, and its analysis entry is also the method where the constant value locates.

For a constant value condition, there is only `targetNumberArr`, which means that only the values in this array are concerned.
For example,
```json
    "ConstNumberMode": true,
    "targetNumberArr": [
      16
    ]
```

## Advanced feature of rules

### TaintTweak

**Note that this section is only for non-whole program analysis mode.**

In the mode of non-whole program analysis, if we want to block the spread of taint, or we know how to spread the taint, or the default rules cannot meet our requirements, then we can specify the taint propagation relationship for each rule individually.

Say,

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

The configuration of these rules is similar to the `VariableFlowRule` in `EngineConfig.json5`. `VariableFlowRule` is for all rules, while TaintTweak is for the current rule.


Then the meaning of the above rule is:
- The method `<android.content.Intent: void <init>(java.lang.String,android.net.Uri,android.content.Context,java.lang.Class)>` will not do any taint propagation.
- A method `putCharSequenceArrayListExtra` also does not do any taint propagation.
