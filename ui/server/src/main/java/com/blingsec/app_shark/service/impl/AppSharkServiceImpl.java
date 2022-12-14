package com.blingsec.app_shark.service.impl;

import com.alibaba.fastjson.JSON;
import com.blingsec.app_shark.common.enums.AssignmentProcessStatus;
import com.blingsec.app_shark.common.exception.BusinessException;
import com.blingsec.app_shark.mapper.AssignmentDao;
import com.blingsec.app_shark.pojo.ConfigJson;
import com.blingsec.app_shark.pojo.vo.AssignmentDetailVo;
import com.blingsec.app_shark.service.AppSharkService;
import com.blingsec.app_shark.service.AssignmentService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.*;
import java.util.Arrays;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.service.impl
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月08日 10:04
 * -------------- -------------- ---------------------
 */
@Service
@Slf4j
public class AppSharkServiceImpl implements AppSharkService {
    @Autowired
    private AssignmentService assignmentService;
    @Autowired
    private AssignmentDao assignmentDao;

    /**
     * 分隔符
     */
    public static final String SEPARATOR = File.separator;
    /**
     * 根路径
     */
    public static final String ROOT_APPSHARK = "/root/appshark/";


    @Override
    @Transactional
    public void saveScan(ConfigJson configJson, AssignmentDetailVo assignmentDetailVo) throws Exception {
        ConfigJson config = new ConfigJson();
        String jobId = configJson.getJobId();
        config.setApkPath(ROOT_APPSHARK + "apps" + SEPARATOR + "files" + SEPARATOR + configJson.getFileName());
        config.setOut("out" + SEPARATOR + jobId);
        config.setRules(configJson.getRules());
        config.setMaxPointerAnalyzeTime(configJson.getMaxPointerAnalyzeTime());

        String jsonArray = JSON.toJSONString(config);
        String configJsonPath = ROOT_APPSHARK + "config" + SEPARATOR + jobId + ".json5";
        BufferedWriter bw = new BufferedWriter(new FileWriter(configJsonPath));
        bw.write(jsonArray);
        bw.close();
        log.info("执行json生成成功:\n" + jsonArray);
        Process exec = null;
        try {
            log.info("调用appSh成功");
            exec = Runtime.getRuntime().exec("java -jar " + ROOT_APPSHARK + "build" + SEPARATOR + "libs" + SEPARATOR + "AppShark-0.1.2-all.jar  " + configJsonPath);
        } catch (Exception e) {
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
        if (StringUtils.isNotBlank(errString) && !errString.contains("ClassCastException")){
            log.error(errString);
            log.error("销毁子进程");
            exec.destroy();
            throw new RuntimeException("扫描启动异常");
        }
        int exitVal = exec.waitFor();
        if (exitVal == 0) {
            assignmentService.syncData();
        } else {
            assignmentDetailVo.setAssignmentProcessStatus(AssignmentProcessStatus.ERROR);
            assignmentDao.updateAssignmentByGuid(assignmentDetailVo);
            assignmentService.scanNextAssignment();
        }
        //都执行完以后删除configJson
        File file = new File(configJsonPath);
        if (file.exists()) {
            boolean d = file.delete();
            if (d) {
                log.info("删除" + configJsonPath + "成功");
            } else {
                log.info("删除" + configJsonPath + "失败");
            }
        }
    }

    @Override
    public String getResult(String guid) {
        String result = "";
        if (StringUtils.isBlank(guid)) {
            throw new BusinessException("参数不可为空");
        }
        ObjectMapper objectMapper = new ObjectMapper();
        String path = ROOT_APPSHARK + "out" + SEPARATOR + guid + SEPARATOR + "results.json";
        File file = new File(path);
        try {
            result = FileUtils.readFileToString(file, "UTF-8");
        } catch (IOException e) {
            log.error("获取结果失败");
        }
        return result;
    }

    @Override
    public String[] getAllRules() {
        String basePath = ROOT_APPSHARK + "config" + SEPARATOR + "rules";
        log.info("获取规则路径为:" + basePath);
        String[] list = new File(basePath).list();
        if (list != null) {
            list = Arrays.stream(list).sorted(String::compareToIgnoreCase).toArray(String[]::new);
        }
        return list;
    }


}