package com.blingsec.app_shark.pojo;

import lombok.Data;

@Data
public class ConfigJson {
    private String apkPath;
    private String out;
    private String rules;
    private int maxPointerAnalyzeTime;
    private String jobId;
    private String fileName;
}
