package com.blingsec.app_shark.pojo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * 认证对象
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Authorization {
    /** 令牌 **/
    private String token;
    /** 登录IP地址信息 **/
    private String loginIpAddress;
    /** 登录时间 **/
    private Date loginTime;
}
