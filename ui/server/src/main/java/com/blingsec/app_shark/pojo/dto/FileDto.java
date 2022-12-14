package com.blingsec.app_shark.pojo.dto;

import lombok.Data;

import java.io.Serializable;

@Data
public class FileDto implements Serializable {
    /** 文件ID **/
    private Long fileId;
    /** 文件名称 **/
    private String fileName;
    /** 文件路径 **/
    private String fileUrl;
    /** 文件加密路径 **/
    private String fileNameNew;
}
