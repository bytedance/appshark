package com.blingsec.app_shark.common.exception;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang.StringUtils;

public class MAPIException extends RuntimeException {
    /** @deprecated */
    @Deprecated
    private String busiCode;
    private JSONObject content;
    private JSONObject log;

    public MAPIException(String message, String busiCode, JSONObject content) {
        this((String)null);
    }

    public MAPIException(String message) {
        super(message);
        this.busiCode = "BASE000";
    }

    protected MAPIException(String message, String busiCode) {
        super(message);
        this.busiCode = "BASE000";
        this.busiCode = busiCode;
    }

    public MAPIException(String message, Throwable e) {
        super(message, e);
        this.busiCode = "BASE000";
    }

    protected MAPIException(String message, String busiCode, Exception e) {
        super(message, e);
        this.busiCode = "BASE000";
        this.busiCode = busiCode;
    }

    public IAPIResult getErrorResult() {
        return CustomExceptionStatus.MAPI_ERROR;
    }

    public String getErrorMessage() {
        return StringUtils.isNotEmpty(this.getMessage()) ? this.getMessage() : this.getErrorResult().getMessage();
    }

    public String getBusiCode() {
        return this.busiCode;
    }

    public JSONObject getContent() {
        return this.content;
    }

    public void setContent(JSONObject content) {
        this.content = content;
    }

    public JSONObject getLog() {
        return this.log;
    }

    public void setLog(JSONObject log) {
        if (this.log == null) {
            this.log = new JSONObject();
        }

        if (log != null) {
            this.log.putAll(log);
        }

    }
}
