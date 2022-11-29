package com.blingsec.app_shark.controller;

import cn.hutool.core.collection.CollectionUtil;
import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.pojo.entity.AppSharkUsePermission;
import com.blingsec.app_shark.pojo.qo.AssignmentCondition;
import com.blingsec.app_shark.pojo.qo.DetailPageConditon;
import com.blingsec.app_shark.pojo.qo.IdsQo;
import com.blingsec.app_shark.pojo.vo.*;
import com.blingsec.app_shark.service.AssignmentService;
import com.github.pagehelper.PageInfo;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.*;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.controller
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月13日 18:04
 * -------------- -------------- ---------------------
 */
@Slf4j
@RestController
@RequestMapping(value = "/assignment")
public class AssignmentController {
    @Autowired
    private AssignmentService assignmentService;
    @Autowired
    private Gson gson;
    @Autowired
    private ExecutorService executorService;

    /**
     * @Author renxin
     * @param assignmentDetailVo
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 新增扫描任务
     * @creat_date 2022年10月17日
     * @creat_time 11:24:22
     */
    @PostMapping("save")
    public ResultEntity save(@Valid @RequestBody AssignmentDetailVo assignmentDetailVo) {
        log.info("任务新增，新增参数信息为：{}", gson.toJson(assignmentDetailVo));
        String save = assignmentService.save(assignmentDetailVo);
        return ResultEntity.success(save);
    }

    /**
     * @Author renxin
     * @param condition
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 任务列表分页查询
     * @creat_date 2022年10月17日
     * @creat_time 11:24:03
     */
    @PostMapping("queryByPage")
    public ResultEntity queryByPage(@RequestBody AssignmentCondition condition) {
        log.info("进入任务管理列表，当前查询条件为：{}", gson.toJson(condition));
        PageInfo<AssignmentPageVo> page = assignmentService.queryByPage(condition);
        return ResultEntity.success(page);
    }

    /**
     * @Author renxin
     * @param qo
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 任务删除
     * @creat_date 2022年10月17日
     * @creat_time 15:55:56
     */
    @PostMapping("batchRemove")
    public ResultEntity remove(@RequestBody IdsQo qo) {
        log.info("任务删除，删除参数信息为：{}", gson.toJson(qo));
        List<Integer> ids = qo.getIds();
        if (CollectionUtil.isEmpty(ids)) {
            return ResultEntity.error("必须选择删除信息");
        }
        int save = assignmentService.remove(ids);
        return ResultEntity.success(save);
    }

    /**
     * @Author renxin
     * @param id
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 任务详情查看
     * @creat_date 2022年10月21日
     * @creat_time 14:04:35
     */
    @GetMapping("detail/{id}")
    public ResultEntity detail(@PathVariable Integer id) {
        log.info("任务详情查看，任务ID为：{}", id);
        AssignmentDetailVo detail = assignmentService.detail(id);
        if (Objects.isNull(detail)) {
            return ResultEntity.error("该数据不存在");
        }
        return ResultEntity.success(detail);
    }

    @PostMapping("testCallBack")
    public ResultEntity testCallBack() {
        assignmentService.syncData();
        return ResultEntity.SUCCESS;
    }

    /**
     * @Author renxin
     * @param condition
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 任务详情权限清单分页查询
     * @creat_date 2022年10月17日
     * @creat_time 11:24:03
     */
    @PostMapping("permission/queryByPage")
    public ResultEntity queryPermissionByPage(@Valid @RequestBody DetailPageConditon condition) {
        log.info("任务详情权限清单分页查询，当前查询条件为：{}", gson.toJson(condition));
        PageInfo<AppSharkUsePermission> page = assignmentService.queryPermissionByPage(condition);
        return ResultEntity.success(page);
    }

    /**
     * @Author renxin
     * @param condition
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 任务详情合规检测分页查询
     * @creat_date 2022年10月17日
     * @creat_time 11:24:03
     */
    @PostMapping("compliance/queryByPage")
    public ResultEntity queryComplianceByPage(@Valid @RequestBody DetailPageConditon condition) {
        log.info("任务详情合规检测分页查询，当前查询条件为：{}", gson.toJson(condition));
        PageInfo<AppSharkCamilleVulnerVo> page = assignmentService.queryComplianceByPage(condition);
        return ResultEntity.success(page);
    }

    /**
     * @Author renxin
     * @param id
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 查询合规检测行为分类
     * @creat_date 2022年10月17日
     * @creat_time 11:24:03
     */
    @GetMapping("compliance/queryCamilleMap/{id}")
    public ResultEntity queryCamilleMap(@PathVariable Integer id) {
        log.info("查询合规检测行为分类，当前查询条件为：{}", gson.toJson(id));
        Map<?, Object> camilleMap = assignmentService.queryCamilleMap(id);
        return ResultEntity.success(camilleMap);
    }

    /**
     * @Author renxin
     * @param condition
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 任务详情漏洞检测类型统计
     * @creat_date 2022年10月17日
     * @creat_time 11:24:03
     */
    @PostMapping("vulner/statisticsType")
    public ResultEntity statisticsType(@Valid @RequestBody DetailPageConditon condition) {
        log.info("任务详情漏洞检测类型统计，当前查询条件为：{}", gson.toJson(condition));
        AppSharkVulnerVo appSharkVulnerVo = assignmentService.statisticsType(condition);
        return ResultEntity.success(appSharkVulnerVo);
    }

    /**
     * @Author renxin
     * @param condition
     * @return com.blingsec.app_shark.pojo.ResultEntity
     * @Description 任务详情漏洞检测分页查询
     * @creat_date 2022年10月17日
     * @creat_time 11:24:03
     */
    @PostMapping("vulner/queryByPage")
    public ResultEntity queryVulnerByPage(@Valid @RequestBody DetailPageConditon condition) {
        log.info("任务详情漏洞检测分页查询，当前查询条件为：{}", gson.toJson(condition));
        PageInfo<AppSharkVulnerInfoVo> pageInfo = assignmentService.queryVulnerByPage(condition);
        return ResultEntity.success(pageInfo);
    }

    @PostMapping("testRunThread")
    public void testRunThread(){
        executorService.submit(() ->{
            Process exec = null;
            try {
                exec = Runtime.getRuntime().exec("java -jar C:\\home\\project\\eureka-1.1.0-SNAPSHOT.jar");
            } catch (IOException e) {
                log.error(e.getMessage());
            }
            System.out.println(exec.pid());
        });
    }

    @PostMapping("testKillThread")
    public void testKillThread(@RequestParam Long pid) throws Exception {
            Process exec = null;
            try {
                //Linux下停止子线程
                exec = Runtime.getRuntime().exec("kill " + pid);
                //windows下停止子线程
//                exec = Runtime.getRuntime().exec("taskkill /F /PID " + pid);
            } catch (IOException e) {
                log.error(e.getMessage());
            }
        // 采用字符流读取缓冲池内容，腾出空间
        BufferedReader reader = new BufferedReader(new InputStreamReader(exec.getInputStream(), "gbk"));
        String line = null;
        while ((line = reader.readLine()) != null){
            System.out.println(line);
        }
        // 采用字符流读取缓冲池内容，腾出空间
        InputStream errorStream = exec.getErrorStream();
        BufferedReader reader1 = new BufferedReader(new InputStreamReader(errorStream, "gbk"));
        StringBuffer errorMessage = new StringBuffer();
        String line1 = null;
        while ((line1 = reader1.readLine()) != null){
            errorMessage.append(line1);
        }
        String errString = errorMessage.toString();
        System.out.println(errString);
    }
}
