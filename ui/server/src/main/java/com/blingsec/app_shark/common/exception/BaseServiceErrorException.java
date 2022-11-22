package com.blingsec.app_shark.common.exception;

import com.alibaba.fastjson.JSONObject;

public class BaseServiceErrorException extends MAPIException {


    public BaseServiceErrorException(String message) {
        super(message, "BASE001");
    }

    public BaseServiceErrorException(String message, String busiCode) {
        super(message, busiCode);
    }
    public BaseServiceErrorException(String message, String busiCode, JSONObject content) {
        super(message, busiCode, content);
    }
    public BaseServiceErrorException(String message, Exception e) {
        super(message, "BASE001", e);
    }

    public BaseServiceErrorException(String message, String busiCode, Exception e) {
        super(message, busiCode, e);
    }

    @Override
    public CustomExceptionStatus getErrorResult() {
        return CustomExceptionStatus.BASE_ERROR;
    }
}
