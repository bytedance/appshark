package com.blingsec.app_shark.controller;

import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.service.ExportService;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * @Project : devsecops_backends
 * @Package Name : com.blingsec.app_shark.controller
 * @Description : 导出功能控制层
 * @Author : renxin
 * @Creation Date : 2022年11月01日 13:22
 * -------------- -------------- ---------------------
 */
@RestController
@RequestMapping("/file/export")
@Slf4j(topic = "ExportController")
public class ExportController {
    @Autowired
    private ExportService exportService;

    @RequestMapping(value = {"/exportScanReport/{assignmentId}"}, produces = {"application/json;charset=UTF-8"})
    public ResultEntity exportScanReport(@PathVariable Integer assignmentId) {
        log.info("扫描报告导出：/file/export/exportScanReport/{assignmentId} 接口调用");
        log.info("扫描报告导出  start： assignmentId:" + assignmentId.toString());
        try {
            String fileName = this.exportService.exportScanReport(assignmentId);
            return ResultEntity.success(fileName);
        }
        //未知异常
        catch (Exception e) {
            log.error("扫描报告导出失败", e);
            return ResultEntity.ERROR;
        }
    }
}