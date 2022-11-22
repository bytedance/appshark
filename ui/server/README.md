## AppShark-ui-server
Appshark-ui-server is a service that renders scan results as user visible ui for the AppShark platform。

## Prerequisites
AppShark-ui-server requires a specific version of JDK
-- [JDK 11](https://www.oracle.com/java/technologies/javase/jdk11-archive-downloads.html). After testing, it does not
work on other LTS versions, JDK 8 and JDK 16, due to the dependency compatibility issue.


## Building/Compiling AppShark-ui-server

-1.搭建MySQL，执行init.sql初始化数据,并对应修改配置文件application-dev.yaml
```yaml
  spring:
  #  数据库连接池配置信息系
  datasource:
    url: jdbc:mysql://127.0.0.1:3306/app_shark?autoReconnect=true&useUnicode=true&characterEncoding=utf8&zeroDateTimeBehavior=convertToNull&useSSL=false&serverTimezone=Asia/Shanghai
    username: root
    password: 123456
```
-2.搭建Redis,并对应修改配置文件application-dev.yaml
```yaml
  # redis 配置信息
  redis:
    host: 127.0.0.1
    port: 6379
    timeout: 5000ms
```
-3.We assume that you are working in the root directory of the project repo. You can build the whole project with the maven tool.

```shell
$ mvn clean install -Dmaven.test.skip -P dev
```


## Running AppShark-ui-server

Like the previous step, we assume that you are still in the root folder of the project. You can run the tool with

 ```shell
 $ java -jar target/app_shark-0.0.1-SNAPSHOT.jar
 ```


## Help
* 如果构造过程出现jdk提示错误而导致无法编译，请重新执行一下，这个问题由于本人太菜，没有解决