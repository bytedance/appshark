package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.common.enums.AssignmentProcessStatus;
import com.blingsec.app_shark.pojo.qo.AssignmentCondition;
import com.blingsec.app_shark.pojo.vo.AssignmentDetailVo;
import com.blingsec.app_shark.pojo.vo.AssignmentPageVo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.mapper
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月14日 17:23
 * -------------- -------------- ---------------------
 */
@Mapper
public interface AssignmentDao {
    /**
     * 添加任务
     */
    void insert(AssignmentDetailVo assignmentDetailVo);
    /**
     * 通过任务状态统计任务数量
     */
    int countProcessStatus(@Param("processStatus") AssignmentProcessStatus processStatus);
    /**
     * 任务分页查询
     */
    List<AssignmentPageVo> queryByPage(AssignmentCondition condition);

    int deleteByIds(@Param("ids") List<Integer> ids);

    void updateByPrimaryKeySelective(AssignmentDetailVo assignmentDetailVo);

    void updateAssignmentByGuid(AssignmentDetailVo assignmentDetailVo);

    AssignmentDetailVo findById(Integer id);

    void insertResultJson(AssignmentDetailVo assignmentDetailVo);
}
