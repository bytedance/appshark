package com.blingsec.app_shark.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Objects;

/**
 * @Project : devsecops
 * @Package Name : com.bling.devsecops.common
 * @Description : 返回数据结果类
 * @Author : renxin
 * @Creation Date : 2021年04月19日 16:49
 * @ModificationHistory Who        When           What
 * -------------- -------------- ---------------------
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResultEntity {
    /**
     * 默认业务状态请求失败
     **/
    private String code;
    /**
     * 返回信息
     **/
    private String message;
    /**
     * 返回数据
     **/
    private Object data;

    public ResultEntity(String code, String message) {
        this.code = code;
        this.message = message;
    }

    /**
     * 通用成功
     **/
    public static final ResultEntity SUCCESS = new ResultEntity(ResultCodeEnum.SUCCESS.getCode(), ResultCodeEnum.SUCCESS.getContext());
    /**
     * 通用失败
     **/
    public static final ResultEntity ERROR = new ResultEntity(ResultCodeEnum.ERROR.getCode(), ResultCodeEnum.ERROR.getContext());
    /**
     * 通用服务器异常
     **/
    public static final ResultEntity SERVER_ERROR = new ResultEntity(ResultCodeEnum.SERVER_ERROR.getCode(), ResultCodeEnum.SERVER_ERROR.getContext());
    public static final ResultEntity PARAM_ERROR = new ResultEntity(ResultCodeEnum.REQUEST_METHOD_NOT_SUPPORT.getCode(), ResultCodeEnum.REQUEST_METHOD_NOT_SUPPORT.getContext());
    public static final ResultEntity UNAUTHORIZED = new ResultEntity(ResultCodeEnum.UNAUTHORIZED.getCode(), ResultCodeEnum.UNAUTHORIZED.getContext());
    public static final ResultEntity FORBIDDEN = new ResultEntity(ResultCodeEnum.FORBIDDEN.getCode(), ResultCodeEnum.FORBIDDEN.getContext());
    public static final ResultEntity REQUEST_METHOD_NOT_SUPPORT = new ResultEntity(ResultCodeEnum.REQUEST_METHOD_NOT_SUPPORT.getCode(), ResultCodeEnum.REQUEST_METHOD_NOT_SUPPORT.getContext());
    public static final ResultEntity NOT_ACCEPTABLE = new ResultEntity(ResultCodeEnum.NOT_ACCEPTABLE.getCode(), ResultCodeEnum.NOT_ACCEPTABLE.getContext());
    public static final ResultEntity FILE_INFO_UPLOAD = new ResultEntity(ResultCodeEnum.FILE_INFO_UPLOAD.getCode(), ResultCodeEnum.FILE_INFO_UPLOAD.getContext());
    public static final ResultEntity FILE_INFO_DOWNLOAD = new ResultEntity(ResultCodeEnum.FILE_INFO_DOWNLOAD.getCode(), ResultCodeEnum.FILE_INFO_DOWNLOAD.getContext());
    // ---------------------------------------认证服务使用状态定义----------------------------------------------------
    /**
     * 登录失败
     **/
    public static final ResultEntity LOGIN_FAIL = new ResultEntity(ResultCodeEnum.LOGIN_FAIL.getCode(), ResultCodeEnum.LOGIN_FAIL.getContext());

    /**
     * 服务不可用
     */
    public static final ResultEntity UNREACHABLE = new ResultEntity("503", "服务不可用");

    /**
     * 通用成功，需要返回数据时使用
     */
    public static ResultEntity success(Object data) {
        return new ResultEntity(ResultCodeEnum.SUCCESS.getCode(), ResultCodeEnum.SUCCESS.getContext(), data);
    }

    /**
     * 通用失败，需要返回数据时使用
     */
    public static ResultEntity error(Object data) {
        return new ResultEntity(ResultCodeEnum.ERROR.getCode(), ResultCodeEnum.ERROR.getContext(), data);
    }

    /**
     * 通用失败，需要自定义消息时使用，一般推荐使用自定义状态码
     */
    public static ResultEntity error(String errorMsg) {
        return new ResultEntity(ResultCodeEnum.ERROR.getCode(), errorMsg);
    }

}
