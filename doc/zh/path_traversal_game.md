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

# appshark深入教程

以一个path traversal的游戏贯穿本教程,让大家体会一下如何发现漏洞,修复漏洞以及如何用appshark发现问题.

## 1. 什么是目录遍历漏洞
根据维基百科定义:
目录遍历（英文：Directory traversal），又名路径遍历（英文：Path traversal）是一种利用网站的安全验证缺陷或用户请求验证缺陷（如传递特定字符串至文件应用程序接口）来列出服务器目录的漏洞利用方式。
此攻击手段的目的是利用存在缺陷的应用程序来获得目标文件系统上的非授权访问权限。与利用程序漏洞的手段相比，这一手段缺乏安全性（因为程序运行逻辑正确）。
目录遍历在英文世界里又名../ 攻击（Dot dot slash attack）、目录攀登（Directory climbing）及回溯（Backtracking）。其部分攻击手段也可划分为规范化攻击（Canonicalization attack）。

## case1: 无任何校验
我们的app有一个content provider,用来共享sandbox目录下的文件. 简单实现如下:
```manifest
<provider
    android:name=".VulProvider1"
    android:authorities="slipme1"
    android:exported="true" />
```

对应的provider是:
```java

public class VulProvider1 extends ContentProvider {

    @Nullable
    @Override
    public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
        File root = getContext().getExternalFilesDir("sandbox");
        String path = uri.getQueryParameter("path");
        return ParcelFileDescriptor.open(new File(root, path), ParcelFileDescriptor.MODE_READ_ONLY);
    }
}
```

你能发现找到其中的问题么? 你能绕过限制,读取到`/data/data/com.security.bypasspathtraversal/files/file2`文件么?

### 如何目录遍历呢?
作者的意图是只共享sandbox目录,但是他直接把用户path作为参数传递给了File,这意味着,如果path中包含"../",那么就可以绕过sandbox目录限制.
可以轻松构造出一个poc:
```java
String path="content://slipme1/?path=../../../../../../../../data/data/com.security.bypasspathtraversal/files/file2";
 String data = IOUtils.toString(getContentResolver().openInputStream(Uri.parse(path)));
```
### 如何利用appshark发现此类漏洞
那么,如何利用利用appshark来自动发现此类漏洞呢? 关键就是定义source,sink以及sanitizer. 
明显openFile的参数0也就是uri是用户可控制的,一般把外部用户可直接或间接控制的变量视为source. 而sink点比较合适的一个地方是`ParcelFileDescriptor.open`的参数0,
因为如果source能够控制`ParcelFileDescriptor.open`参数0,那么基本上就可以读取任何文件了.

因此source,sink定义如下:
```json
{
  "source": {
    "Param": {
      "<*: android.os.ParcelFileDescriptor openFile(*)>": [
        "p0"
      ]
    }
  },
  "sink": {
    "<android.os.ParcelFileDescriptor: android.os.ParcelFileDescriptor open(java.io.File,int)>": {
      "TaintCheck": [
        "p0"
      ]
    }
  }
}
```
### 完整的规则
```json
{
  "ContentProviderPathTraversal": {
    "enable": true,
    "SliceMode": true,
    "traceDepth": 14,
    "desc": {
      "name": "ContentProviderPathTraversal",
      "category": "",
      "wiki": "",
      "detail": "如果Content Provider重写了openFile，但是没有对Uri进行路径合法性校验，那么攻击者可能通过在uri中插入../的方式访问预期外的文件",
      "possibility": "",
      "model": ""
    },
    "source": {
      "Param": {
        "<*: android.os.ParcelFileDescriptor openFile(*)>": [
          "p0"
        ]
      }
    },
    "sink": {
      "<android.os.ParcelFileDescriptor: android.os.ParcelFileDescriptor open(java.io.File,int)>": {
        "TaintCheck": [
          "p0"
        ]
      }
    }
  }
}
```

### 验证

app完整的源码位于 [BypassPathTraversal](https://github.com/nkbai/BypassPathTraversal). apk文件也在这个repo中[下载apk](https://github.com/nkbai/BypassPathTraversal/blob/main/apk/app-debug.apk).
完整的config文件:
```json
{
  //apk to anlayze
  "apkPath": "/Users/bai/Downloads/traversal/BypassPathTraversal/app/build/outputs/apk/debug/app-debug.apk",
  //result output directory
  "out": "out",
  "rules": "ContentProviderPathTraversal.json",
  "maxPointerAnalyzeTime": 600
}
```
运行命令如下:
```shell
java -jar AppShark-0.1.1-all.jar config/config.json5
```

可以在out目录中的results.json中发现下面的内容:
```json
{
    "details": {
        "Sink": [
            "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>->$r5"
        ],
        "position": "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>",
        "Manifest": {
            "exported": true,
            "trace": [
                "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>"
            ],
            "<provider exported=true name=com.security.bypasspathtraversal.VulProvider1 authorities=slipme1>": [
            ]
        },
        "entryMethod": "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>",
        "Source": [
            "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>->@parameter0"
        ],
        "url": "out/vulnerability/6-ContentProviderPathTraversal.html",
        "target": [
            "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>->@parameter0",
            "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>->$r1",
            "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>->$r2_1",
            "<com.security.bypasspathtraversal.VulProvider1: android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)>->$r5"
        ]
    },
    "hash": "186d1273a64ac711c703e259ce0329fa8a25cf37",
    "possibility": ""
}
```
[更多关于result格式的解读看这里](startup.md)

其中`6-ContentProviderPathTraversal.html`中有更加可视化的数据流图. 想要看明白完整的数据流,需要大家对jimple有一定的了解,[查看更多jimple的知识](http://soot-oss.github.io/soot/).

## case2: getLastPathSegment
发现了漏洞,那么肯定要修复它, 该如何修复呢,这里提供一个修复方式. 通过仔细观察用户传入的路径:
`content://slipme1/?path=../../../../../../../../data/data/com.security.bypasspathtraversal/files/file2`
关键问题是我们的`new File(root, path)`,他实际上做了一个直接的路径拼接,那么只要我不这么做就行了. 
一个思路是我希望传入的路径是:`content://slipme2/somefile`,出于安全考虑,**只允许访问sandbox目录下的文件,其子目录下的文件则不可以读取**.
因此,新的设计如下:
```java
public class VulProvider2 extends ContentProvider {

    @Nullable
    @Override
    public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
        File root = getContext().getExternalFilesDir("sandbox");
        String path = uri.getQueryParameter("path");
        return ParcelFileDescriptor.open(new File(root, uri.getLastPathSegment()), ParcelFileDescriptor.MODE_READ_ONLY);
    }
}
```
这时候如果用户传入的uri是: `content://slipme2/../../../../../../../../data/data/com.security.bypasspathtraversal/files/file2`,
那么将只会截取最后的file2作为文件名. 经过发现确实如此. 

### 如何避免误报呢?
如果我们用appshark扫描修复后的代码,会发现依然会报漏洞,这可不是我们希望看到的. 那么怎么避免误报呢? 这就需要sanitizer了. 
通过观察修复后的代码发现,这次它是通过`uri.getLastPathSegment()`来获取的路径. 因此可以认为,如果从source传播到sink的路径上,
有`uri.getLastPathSegment()`这样的调用,那么可以认为漏洞已经修复.

因此添加sanitizer如下:
```json
{
  "sanitizer": {
    "getLastPathSegment": {
      "<android.net.Uri: java.lang.String getLastPathSegment()>": {
        "TaintCheck": [
          "@this"
        ]
      }
    }
  }
}
```
如果调用了`uri.getLastPathSegment()`,并且this指针被source污染了,那么可以认为漏洞修复了.
被污染了的准确含义是,可能被控制. 比如c=a+b,那么c就被a和b污染了.

同样按照刚刚的方法重新扫描一下,发现`VulProvider1`的漏洞存在,但是`VulProvider2`的漏洞已经消失了.


### 真的修复了?
这里要翻转一下,真的修复了么? 
别忘了URL编码问题,如果我们传输的不是`content://slipme2/../../../../../../../../data/data/com.security.bypasspathtraversal/files/file2`,
而是`content://slipme2/encoded/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fdata%2Fdata%2Fcom%2Esecurity%2Ebypasspathtraversal%2Ffiles%2Ffile2`,是否可以呢?

可以验证,VulProvider2也并不是一个有效的修复,仍然有漏洞存在.


## case3 检查..
既然目录遍历漏洞,又称为`Dot dot slash attack`, 说明其核心就是路径中的"../",是关键特征,我们这次直接从这个特征入手,如果path中包含了..,
那么就认为是非法路径即可.

因此,此次修复方法为:
```java
public class VulProvider3 extends ContentProvider {

    @Nullable
    @Override
    public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
        File root = getContext().getExternalFilesDir("sandbox");

        String path = uri.getQueryParameter("path");
        File file3 = new File(path);
        File internalDir = getContext().getFilesDir();
        try {
             if (path.contains("..") || path.startsWith(internalDir.getCanonicalPath())) {
                throw new IllegalArgumentException();
            }
        } catch (IOException e) {
            throw new IllegalArgumentException();
        }
        return ParcelFileDescriptor.open(file3, ParcelFileDescriptor.MODE_READ_ONLY);

    }
 
}
```

注意到这里的条件是两者都不满足:
1. 包含了..
2. 路径不能以内部路径开头

可以很快确认,前两种绕过方式,都已经失效了.


### 如何避免误报呢?

针对这次修复,怎么才能不误报呢? 还是观察这里的限定条件:
1. 包含了..
2. 路径不能以内部路径开头

我们不难想到就是下面的sanitizer:
```json
{
    "sanitizer": {
 
      "containsDotdot": {
        "<java.lang.String: boolean contains(java.lang.CharSequence)>": {
          "TaintCheck": [
            "@this"
          ],
          "p0": [
            "..*"
          ]
        },
        "<java.lang.String: boolean startsWith(java.lang.String)>": {
          "TaintCheck": [
            "@this"
          ]
        }
      }
    }
}
```
那么这个sanitizer的准确含义是什么呢?
针对一条从source到sink的路径上,如果:
1. String.contains的this指针被污染了,并且这个函数调用位置的p0参数能够被"..*"这个常量污染到
2. 并且String.startWith的this指针也被污染了.

被污染了的准确含义是,可能被控制. 比如c=a+b,那么c就被a和b污染了.

同样按照刚刚的方法重新扫描一下,发现`VulProvider1`,`VulProvider2`的漏洞存在,但是`VulProvider3`的漏洞已经消失了.

### 再次反转,真的修复了么?
你能否想到绕过的方式呢?




对,那就是软链接,这里有一个明显的问题,就是他校验是如果以app的内部路径开头,就抛出异常. 我们可以通过软链接,既不包含..,也不以app的内部路径开头.
poc代码如下:
```java
String root = getApplicationInfo().dataDir;
String symlink = root + "/symlink";
android_command("ln -sf /data/data/com.security.bypasspathtraversal/files/file2 " + symlink);
android_command("chmod -R 777 " + root);
String path="content://slipme3/?path=" + symlink;
String data = IOUtils.toString(getContentResolver().openInputStream(Uri.parse(path)));
```


## case4 彻底的修复
可以存在两种有效的修复方式:

### 修复方式1

```java
public class VulProvider6 extends ContentProvider {

    @Nullable
    @Override
    public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
        File root = getContext().getExternalFilesDir("sandbox");

        String path = uri.getQueryParameter("path");
        File file3 = new File(path);
        try {
            if (path.contains("..") || path.startsWith(root.getPath())) {
                throw new IllegalArgumentException();
            }
        } catch (IOException e) {
            throw new IllegalArgumentException();
        }
        return ParcelFileDescriptor.open(file3, ParcelFileDescriptor.MODE_READ_ONLY);

    }
}

```
注意这里的startsWith 检查的是sandbox的path,所以我们就没法在自己的目录中创建一个软链接了.

### 修复方式2

```java
public class VulProvider5 extends ContentProvider {

    @Nullable
    @Override
    public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
        File root = getContext().getExternalFilesDir("sandbox");
        File file5 = new File(getContext().getExternalFilesDir("sandbox"), uri.getLastPathSegment());
        try {
            file5 = file5.getCanonicalFile();
            if (!file5.getPath().startsWith(root.getCanonicalPath())) {
                throw new IllegalArgumentException();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ParcelFileDescriptor.open(file5, ParcelFileDescriptor.MODE_READ_ONLY);

    }
}
```
这里通过`getCanonicalFile`来解析软链接,这样获取到的就是真实的路径了. 所以这里的条件是:
1. 通过getCanonicalFile获取到真实的路径
2. 通过startsWith校验真实路径是否以sandbox路径开头.

这种两种方式都ok,那么如果用了第二种方式,我们怎么避免误报呢?

不难想到这样的sanitizer:
```json
{
    "getCanonicalFile": {
      "<java.io.File: java.io.File getCanonicalFile()>": {
        "TaintCheck": [
          "@this"
        ]
      },
      "<java.lang.String: boolean startsWith(java.lang.String)>": {
        "TaintCheck": [
          "@this"
        ]
      }
    }
}
```
这个规则校验的是:
1. getCanonicalFile的this指针要被source污染.
2. startsWith的this指针也要被source污染.

因此最终的完整规则如下:
```json
{
  "ContentProviderPathTraversal": {
    "SliceMode": true,
    "traceDepth": 14,
    "desc": {
      "name": "ContentProviderPathTraversal",
      "category": "",
      "wiki": "",
      "detail": "如果Content Provider重写了openFile，但是没有对Uri进行路径合法性校验，那么攻击者可能通过在uri中插入../的方式访问预期外的文件",
      "possibility": "",
      "model": ""
    },
    "source": {
      "Param": {
        "<*: android.os.ParcelFileDescriptor openFile(*)>": [
          "p0"
        ]
      }
    },
    "sink": {
      "<android.os.ParcelFileDescriptor: android.os.ParcelFileDescriptor open(java.io.File,int)>": {
        "TaintCheck": [
          "p0"
        ]
      }
    },
    "sanitizer": {
      "getCanonicalFile": {
        "<java.io.File: java.io.File getCanonicalFile()>": {
          "TaintCheck": [
            "@this"
          ]
        },
        "<java.lang.String: boolean startsWith(java.lang.String)>": {
          "TaintCheck": [
            "@this"
          ]
        }
      },
      "containsDotDot": {
        "<java.lang.String: boolean contains(java.lang.CharSequence)>": {
          "TaintCheck": [
            "@this"
          ],
          "p0": [
            "..*"
          ]
        },
        "<java.lang.String: boolean startsWith(java.lang.String)>": {
          "TaintCheck": [
            "@this"
          ]
        }
      }
    }
  }
}


```

## 误报/漏报是无法彻底避免的

大家可能有疑问.containsDotDot这个sanitizer存在漏报问题啊,`case3`中的修复方式明明是无效的,但是仍然会被引擎因为是修复了的,这实际上导致了漏报.
这里只能说一下sanitizer的局限性了,它只能根据source污染到的变量的范围来确定要不要去掉一条路径. 真实的修复方式:
`path.startsWith(root.getPath())`和有问题的修复方式` path.startsWith(internalDir.getCanonicalPath())`从形式上看是没什么区别的. 
让appshark去识别这种逻辑上的区别,是非常困难的, 这也是appshark的局限.

## 写在最后

appshark是一个实用的基于指针分析的静态分析工具,虽然可以对大型app进行分析,但是不可避免的存在局限性,希望大家能够扬长避短,
在appshark擅长的领域发挥出它的价值, 也为自己的日常工作带来帮助.

另外,这里有完整的[appshark规则的撰写手册](how_to_write_rules.md)
