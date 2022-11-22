package com.blingsec.app_shark.pojo.qo;

import com.blingsec.app_shark.common.enums.AssignmentProcessStatus;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;
import java.util.List;

/**
 * @author renxin
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class AssignmentCondition extends BaseCondition implements Serializable {
    /** 任务名称 **/
    private String assignmentName;
    /** 任务状态 **/
    private AssignmentProcessStatus assignmentProcessStatus;
    /** id列表 **/
    private List<Integer> ids;
}
