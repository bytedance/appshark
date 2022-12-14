package com.blingsec.app_shark.service.impl;

import cn.hutool.core.collection.CollectionUtil;
import com.blingsec.app_shark.common.enums.VulnerLevelEnum;
import com.blingsec.app_shark.pojo.dto.ExcelExp;
import com.blingsec.app_shark.pojo.entity.*;
import com.blingsec.app_shark.pojo.qo.DetailPageConditon;
import com.blingsec.app_shark.pojo.vo.AppSharkCamilleVulnerVo;
import com.blingsec.app_shark.pojo.vo.AppSharkVulnerInfoVo;
import com.blingsec.app_shark.pojo.vo.AppSharkVulnerVo;
import com.blingsec.app_shark.pojo.vo.AssignmentDetailVo;
import com.blingsec.app_shark.service.AssignmentService;
import com.blingsec.app_shark.service.ExportService;
import com.blingsec.app_shark.util.DateUtil;
import com.github.pagehelper.PageInfo;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.Workbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static com.blingsec.app_shark.util.ExcelExportUtil.exportManySheetExcel;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.service.impl
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月28日 10:32
 * -------------- -------------- ---------------------
 */
@Service
@Slf4j
public class ExportServiceImpl implements ExportService {
    //在文件操作中，不用/或者\最好，推荐使用File.separator
    public static final String ROOT_APPSHARK = "/root/appshark";
    //在文件操作中，不用/或者\最好，推荐使用File.separator
    private final static String fileDir = File.separator + "apps" + File.separator + "files" + File.separator;
    private final static String rootPath = ROOT_APPSHARK + fileDir;
    @Autowired
    private AssignmentService assignmentService;


    @Override
    public String exportScanReport(Integer assignmentId) {
        DetailPageConditon detailPageConditon = new DetailPageConditon();
        detailPageConditon.setAssessmentId(assignmentId);
        detailPageConditon.setPage(1);
        detailPageConditon.setRows(Integer.MAX_VALUE);
        //1.首先获取任务基本信息
        AssignmentDetailVo detail = assignmentService.detail(assignmentId);
        //2.获取权限清单列表
        PageInfo<AppSharkUsePermission> appSharkUsePermissionPageInfo = assignmentService.queryPermissionByPage(detailPageConditon);
        //3.获取合规检测列表
        PageInfo<AppSharkCamilleVulnerVo> appSharkCamilleVulnerVoPageInfo = assignmentService.queryComplianceByPage(detailPageConditon);
        //4.获取漏洞扫描列表
        PageInfo<AppSharkVulnerInfoVo> pageInfo = assignmentService.queryVulnerByPage(detailPageConditon);

        //5.封装将要导出的结构
        /** 第一页数据 */
        Map<String, Object> dataAllOne = Maps.newHashMap();
        dataAllOne.put("detail",detail);
        dataAllOne.put("appSharkUsePermissionPageInfo",appSharkUsePermissionPageInfo);
        /** 第二页数据 */
        List<List<String>> dataAllTwo = new ArrayList<>();
        List<AppSharkCamilleVulnerVo> appSharkCamilleVulnerVoList = appSharkCamilleVulnerVoPageInfo.getList();
        if (CollectionUtil.isNotEmpty(appSharkCamilleVulnerVoList)){
            //序号
            AtomicReference<Integer> sequence = new AtomicReference<>(1);
            appSharkCamilleVulnerVoList.forEach(appSharkCamilleVulnerVo -> {
                String targets = appSharkCamilleVulnerVo.getTargets().toString();
                List<String> data = Arrays.asList(sequence.toString(),
                        appSharkCamilleVulnerVo.getName(),
                        appSharkCamilleVulnerVo.getPosition(),
                        targets.substring(1, targets.length() - 1));
                dataAllTwo.add(data);
                sequence.updateAndGet(v -> v+1);
            });
        }
        /** 第三页数据 */
        List<List<String>> dataAllThree = new ArrayList<>();
        if (Objects.nonNull(pageInfo)){
            List<AppSharkVulnerInfoVo> appSharkVulnerVoList = pageInfo.getList();
            if (CollectionUtil.isNotEmpty(appSharkVulnerVoList)){
                //序号
                AtomicReference<Integer> sequence = new AtomicReference<>(1);
                appSharkVulnerVoList.forEach(appSharkVulnerInfoVo -> {
                    AppSharkTraversalVulner appSharkTraversalVulner = appSharkVulnerInfoVo.getAppSharkTraversalVulner();
                    List<String> data = Arrays.asList(sequence.toString(),
                            VulnerLevelEnum.getValue(appSharkVulnerInfoVo.getModel()),
                            appSharkVulnerInfoVo.getName(),
                            appSharkVulnerInfoVo.getCategory(),
                            appSharkVulnerInfoVo.getDetail(),
                            appSharkTraversalVulner.getPosition(),
                            appSharkTraversalVulner.getEntryMethod(),
                            appSharkVulnerInfoVo.getAppSharkTraversalSources().stream().map(AppSharkTraversalSource::getSource).collect(Collectors.joining(",")),
                            appSharkVulnerInfoVo.getAppSharkTraversalTargets().stream().map(AppSharkTraversalTarget::getTarget).collect(Collectors.joining(",")),
                            appSharkVulnerInfoVo.getAppSharkTraversalSinks().stream().map(AppSharkTraversalSink::getSink).collect(Collectors.joining(",")),
                            appSharkTraversalVulner.getUrl());
                    dataAllThree.add(data);
                    sequence.updateAndGet(v -> v+1);
                });
            }
        }
        ArrayList<ExcelExp> list = new ArrayList<>();
        ExcelExp excelExp1 = new ExcelExp("任务及App信息", dataAllOne,true);
        ExcelExp excelExp2 = new ExcelExp("查看合规检测结果", Arrays.asList("序号", "行为", "位置", "堆栈"), dataAllTwo,false);
        ExcelExp excelExp3 = new ExcelExp("查看漏洞检测结果", Arrays.asList("序号", "漏洞级别", "漏洞名称", "漏洞类型","漏洞描述","位置","分析入口","传播起点","传播路径","传播终点","详情"), dataAllThree,false);
        list.add(excelExp1);
        list.add(excelExp2);
        list.add(excelExp3);

        Workbook workbook = exportManySheetExcel(list);

        //获取当前时间戳
        String now = DateUtil.date2String(new Date(), DateUtil.DATE_TIME_YNDHMS_PATTERN);
        String fileName = detail.getAssignmentName() + "_" + now + ".xls";
        this.checkRootFilePathExistsAndMkdir();
        String path = rootPath + "" + fileName;
        //导出数据到excel
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(path);
            workbook.write(fileOutputStream);
            fileOutputStream.flush();
        } catch (FileNotFoundException e) {
            log.error(e.getMessage());
        } catch (IOException e) {
            log.error(e.getMessage());
        } finally {
            if(fileOutputStream != null){
                try {
                    fileOutputStream.close();
                } catch (IOException e) {
                    log.error(e.getMessage());
                }
            }
        }
        return fileName;
    }

    private void checkRootFilePathExistsAndMkdir() {
        File dir = new File(rootPath);
        if (dir.exists()) {
            return;
        }
        if (dir.isDirectory()) {
            return;
        }
        dir.mkdirs();
    }
}
