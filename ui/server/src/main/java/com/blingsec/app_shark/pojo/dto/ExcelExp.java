package com.blingsec.app_shark.pojo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.dto
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月21日 14:40
 * -------------- -------------- ---------------------
 */
@Data
public class ExcelExp {
    private String fileName;// sheet的名称
    private List<String> handers;// sheet里的标题
    private List<List<String>> dataset;// sheet里的数据集
    private Map<String,Object> definedData;//自定义数据
    private Boolean definedStatus;

    public ExcelExp() {
    }

    public ExcelExp(String fileName, List<String> handers, List<List<String>> dataset,Boolean definedStatus) {
        this.fileName = fileName;
        this.handers = handers;
        this.dataset = dataset;
        this.definedStatus = definedStatus;
    }

    public ExcelExp(String fileName, Map<String, Object> definedData,Boolean definedStatus) {
        this.fileName = fileName;
        this.definedData = definedData;
        this.definedStatus = definedStatus;
    }
}
