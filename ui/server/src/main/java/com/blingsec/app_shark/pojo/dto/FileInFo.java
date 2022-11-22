package com.blingsec.app_shark.pojo.dto;

import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
public class FileInFo implements Serializable {

    //主键id
    private Long fileId;
    //源文件名称
    private String fileNameOld;
    //加密后文件名
    private String fileNameNew;
    //文集类型
    private String fileType;
    //文件路径
    private String fileStorgePath;
    //创建时间
    private Date ctime;
    //更新时间
    private Date mtime;

}
