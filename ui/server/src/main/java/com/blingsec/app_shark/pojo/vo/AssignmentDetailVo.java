package com.blingsec.app_shark.pojo.vo;

import com.blingsec.app_shark.common.base.OrgIdEntity;
import com.blingsec.app_shark.common.enums.AssignmentProcessStatus;
import com.blingsec.app_shark.common.enums.IsFlag;
import com.blingsec.app_shark.pojo.dto.FileDto;
import com.blingsec.app_shark.pojo.entity.AppSharkAppInfo;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * @author renxin
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class AssignmentDetailVo extends OrgIdEntity implements Serializable {
    /** 任务名称 **/
    @NotBlank(message = "任务名称不能为空")
    @Length(max = 20, message = "任务名称超出允许范围")
    private String assignmentName;
    /** 任务描述 **/
    @Length(max = 500, message = "任务描述超出允许范围")
    private String assignmentDescription;
    /** 任务状态 **/
    private AssignmentProcessStatus assignmentProcessStatus;
    /** app文件id **/
    @NotNull(message = "App文件不能为空")
    private Long appAttachId;
    /** 最大点分析时间（单位：秒） **/
    private Integer largestAnalysis;
    /** 规则列表以逗号分割 **/
    @NotNull(message = "规则不能为空")
    private List<String> preRules;
    private String rules;
    /** 解析状态 **/
    private IsFlag analysisStatus;
    /** 结果json **/
    private String resultJson;
    /** 扫描时间 **/
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date scanTime;
    /** Apk文件 **/
    private FileDto appAttach;
    /** App基本信息 **/
    private AppSharkAppInfo appSharkAppInfo;
    /** 扫描进程的PID **/
    private Long pid;
}
