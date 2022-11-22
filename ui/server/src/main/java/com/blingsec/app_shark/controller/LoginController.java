package com.blingsec.app_shark.controller;

import com.alibaba.druid.util.StringUtils;
import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.pojo.dto.Authorization;
import com.blingsec.app_shark.pojo.qo.PasswordQo;
import com.blingsec.app_shark.service.TokenService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Objects;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.controller
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月13日 18:10
 * -------------- -------------- ---------------------
 */
@Slf4j
@RestController
@RequestMapping(value = "/login")
public class LoginController {
    @Autowired
    private TokenService tokenService;

    @PostMapping(value = "/normalLogin")
    public ResultEntity normalLogin(@RequestBody PasswordQo passwordQo){
        if (!StringUtils.equals(passwordQo.getPassword(),"a123456")){
            return ResultEntity.LOGIN_FAIL;
        }
        String loginToken = tokenService.generateToken("admin");
        String ip = this.getIpAddress();
        Authorization authorization = new Authorization(loginToken, ip, new Date());
        //生成token存到redis中
        tokenService.putAuthorizationWithToken(loginToken, authorization);
       return ResultEntity.success(authorization);
    }

    private String getIpAddress() {
        HttpServletRequest request = this.getHttpServletRequest();
        // 获取请求主机IP地址,如果通过代理进来，则透过防火墙获取真实IP地址
        String ip = request.getHeader("X-Forwarded-For");

        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
                ip = request.getHeader("Proxy-Client-IP");
            }
            if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
                ip = request.getHeader("WL-Proxy-Client-IP");
            }
            if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
                ip = request.getHeader("HTTP_CLIENT_IP");
            }
            if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
                ip = request.getHeader("HTTP_X_FORWARDED_FOR");
            }
            if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
                ip = request.getRemoteAddr();
            }
        } else if (ip.length() > 15) {
            String[] ips = ip.split(",");
            for (int index = 0; index < ips.length; index++) {
                String strIp = (String) ips[index];
                if (!("unknown".equalsIgnoreCase(strIp))) {
                    ip = strIp;
                    break;
                }
            }
        }
        return ip;
    }

    protected HttpServletRequest getHttpServletRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (Objects.isNull(requestAttributes)) {
            return null;
        }
        return ((ServletRequestAttributes) requestAttributes).getRequest();
    }
}
