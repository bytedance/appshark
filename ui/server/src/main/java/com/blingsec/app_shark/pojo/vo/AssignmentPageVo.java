package com.blingsec.app_shark.pojo.vo;

import com.blingsec.app_shark.common.enums.AssignmentProcessStatus;
import com.blingsec.app_shark.common.enums.IsFlag;
import com.blingsec.app_shark.pojo.dto.FileDto;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

/**
 * @author renxin
 */
@Data
public class AssignmentPageVo implements Serializable {
    /** 任务ID **/
    private Integer id;
    /** 任务编号 **/
    private String guid;
    /** 任务名称 **/
    private String assignmentName;
    /** 规则列表以逗号分割 **/
    private String rules;
    /** 任务状态 **/
    private AssignmentProcessStatus processStatus;
    /** 任务创建时间 **/
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date createdAt;
    /** 扫描时间 **/
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date scanTime;
    /** Apk文件 **/
    private FileDto appAttach;
    /** 解析状态 **/
    private IsFlag analysisStatus;
}
