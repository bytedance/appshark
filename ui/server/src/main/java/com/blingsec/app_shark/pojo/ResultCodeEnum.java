package com.blingsec.app_shark.pojo;

/**
 * @Project : devsecops
 * @Package Name : com.blingsec.app_shark.pojo
 * @Description : 返回数据结果类
 * @Author : renxin
 * @Creation Date : 2021年10月19日 16:49
 * @ModificationHistory Who        When           What
 * -------------- -------------- ---------------------
 */
public enum ResultCodeEnum {

    //--------------------通用处理-------------------
    SUCCESS("200", "成功"),
    ERROR("-1", "失败"),
    SERVER_ERROR("500", "网络异常"),
    REQUEST_METHOD_NOT_SUPPORT("400", "不支持的请求方式"),
    UNAUTHORIZED("401", "未经授权的访问"),
    FORBIDDEN("403", "您没有访问该资源的权限"),
    NOT_ACCEPTABLE("406", "请求消息体错误"),
    FILE_INFO_DOWNLOAD("3002", "下载失败"),
    FILE_INFO_UPLOAD("3001", "上传失败"),
    //--------------------账号模块相关-------------------
    LOGIN_FAIL("1003", "密码错误");

    private final String code;
    private final String context;

    public String getContext() {
        return this.context;
    }

    public String getCode() {
        return code;
    }

    private ResultCodeEnum(String code, String context) {
        this.code = code;
        this.context = context;
    }
}
