How to get started quickly, take a simple vulnerability scan as an example

# 1. Download jar dependencies

the jar file  can be [downloaded here](https://github.com/bytedance/appshark/releases/download/v0.1.1/AppShark-0.1.1-all.jar). Install jre/jdk 11 for our engine.

# 2. Download the config folder on Github

```shell
git clone  https://github.com/bytedance/appshark
```

# 3. Update the config file

1. Change apkPath to the target apk file's absolute path.
2. Specify the rule(s) to be applied, separated by a comma. The rules should locate in the config/rules folder, since Appshark searches this folder for the rules.
3. Specify the output folder of the results. Its default value is ./out folder, you can change it to any other directory.

# 4. Run Appshark

```shell
java -jar AppShark-0.1.1-all.jar config/config.json5
```

# 5. Check out results
The results locate in the output folder (./out by default). The results.json file gives the detected vulnerability list. A detailed explanation can be found in [result.md](result.md).
If you have questions about a specific vulnerability, you can check the file provided by the url field.