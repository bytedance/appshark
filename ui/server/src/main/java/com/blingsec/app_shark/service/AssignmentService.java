package com.blingsec.app_shark.service;

import com.blingsec.app_shark.pojo.entity.AppSharkUsePermission;
import com.blingsec.app_shark.pojo.qo.AssignmentCondition;
import com.blingsec.app_shark.pojo.qo.DetailPageConditon;
import com.blingsec.app_shark.pojo.vo.*;
import com.github.pagehelper.PageInfo;

import java.util.List;
import java.util.Map;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.service
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月13日 18:06
 * -------------- -------------- ---------------------
 */
public interface AssignmentService {
    /**新增扫描任务**/
    String save(AssignmentDetailVo assignmentDetailVo);

    /**任务列表分页查询**/
    PageInfo<AssignmentPageVo> queryByPage(AssignmentCondition condition);

    /**任务删除**/
    int remove(List<Integer> ids);

    void syncData();

    void scanNextAssignment();

    /** 任务详情查看 **/
    AssignmentDetailVo detail(Integer id);

    /** 任务详情权限清单分页查询 **/
    PageInfo<AppSharkUsePermission> queryPermissionByPage(DetailPageConditon condition);

    /** 任务详情漏洞检测分页查询 **/
    PageInfo<AppSharkVulnerInfoVo> queryVulnerByPage(DetailPageConditon condition);

    /** 查询合规检测行为分类 **/
    Map<? extends Object, Object> queryCamilleMap(Integer id);

    PageInfo<AppSharkCamilleVulnerVo> queryComplianceByPage(DetailPageConditon condition);

    AppSharkVulnerVo statisticsType(DetailPageConditon condition);
}
