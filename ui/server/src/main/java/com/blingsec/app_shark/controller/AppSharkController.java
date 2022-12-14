package com.blingsec.app_shark.controller;

import com.blingsec.app_shark.pojo.ConfigJson;
import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.service.AppSharkService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.controller
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月08日 10:03
 * -------------- -------------- ---------------------
 */
@RestController
@RequestMapping(value = "/appShark")
@Slf4j(topic = "AppSharkController")
public class AppSharkController {
    @Autowired
    private AppSharkService appSharkService;

    @GetMapping("/getResult")
    public ResultEntity getResult(@RequestParam("guid") String guid) {
        return ResultEntity.success(appSharkService.getResult(guid));
    }

    @GetMapping("/getAllRules")
    public ResultEntity getAllRules() {
        return ResultEntity.success(appSharkService.getAllRules());
    }
}
