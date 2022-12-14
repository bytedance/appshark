package com.blingsec.app_shark.service;

import com.blingsec.app_shark.pojo.ConfigJson;
import com.blingsec.app_shark.pojo.vo.AssignmentDetailVo;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.service.impl
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月08日 10:04
 * -------------- -------------- ---------------------
 */
public interface AppSharkService {
    /**
     * 发起扫描
     *
     * @param config
     * @throws Exception
     */
    void saveScan(ConfigJson config, AssignmentDetailVo assignmentDetailVo) throws Exception;

    /**
     * 获取结果
     *
     * @param guid
     * @return
     */
    String getResult(String guid);

    /**
     * 获取所有规则
     *
     * @return
     */
    String[] getAllRules();
}
