package com.blingsec.app_shark;

import cn.hutool.core.exceptions.ExceptionUtil;
import com.blingsec.app_shark.common.exception.BaseServiceErrorException;
import com.blingsec.app_shark.common.exception.BusinessException;
import com.blingsec.app_shark.pojo.ResultEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.multipart.MultipartException;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@ControllerAdvice
@RestController
@Slf4j
public class MainController {
    @ExceptionHandler({MethodArgumentNotValidException.class})
    public ResultEntity handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        BindingResult bindingResult = ex.getBindingResult();
        StringBuilder sb = new StringBuilder("");
        for (FieldError fieldError : bindingResult.getFieldErrors()) {
            sb.append(fieldError.getDefaultMessage()).append(";");
        }
        String msg = sb.toString();
        return ResultEntity.error(msg);
    }

    @ExceptionHandler({Throwable.class})
    public ResultEntity exceptionHandler(Throwable ex) {
        if (ExceptionUtil.isCausedBy(ex, HttpRequestMethodNotSupportedException.class)) {
            log.error("请求方式错误", ex);
            return ResultEntity.REQUEST_METHOD_NOT_SUPPORT;
        }
        if (ExceptionUtil.isCausedBy(ex, HttpMessageNotReadableException.class)) {
            log.error("请求参数解析失败", ex);
            return ResultEntity.NOT_ACCEPTABLE;
        }
        if (ExceptionUtil.isCausedBy(ex, HttpServerErrorException.class)) {
            HttpServerErrorException e = (HttpServerErrorException) ex;
            log.error("调用第三方接口实现错误，{}", e.getResponseBodyAsString());
            if (Objects.equals(e.getStatusCode(), HttpStatus.UNAUTHORIZED)) {
                return ResultEntity.error("未授权的访问");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.NOT_FOUND)) {
                return ResultEntity.error("地址不存在，请联系管理员进行确认");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.METHOD_NOT_ALLOWED)) {
                return ResultEntity.error("请求方式错误");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.BAD_REQUEST)) {
                return ResultEntity.error("参数异常");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.UNSUPPORTED_MEDIA_TYPE)) {
                return ResultEntity.error("请求头错误");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.INTERNAL_SERVER_ERROR)) {
                return ResultEntity.error("服务异常");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.SERVICE_UNAVAILABLE)) {
                return ResultEntity.error("服务不存在");
            }
        }
        if (ExceptionUtil.isCausedBy(ex, HttpClientErrorException.class)) {
            HttpClientErrorException e = (HttpClientErrorException) ex;
            log.error("调用第三方接口实现错误，{}", e.getResponseBodyAsString());
            if (Objects.equals(e.getStatusCode(), HttpStatus.UNAUTHORIZED)) {
                return ResultEntity.error("未授权的访问");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.NOT_FOUND)) {
                return ResultEntity.error("地址不存在，请联系管理员进行确认");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.METHOD_NOT_ALLOWED)) {
                return ResultEntity.error("请求方式错误");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.BAD_REQUEST)) {
                return ResultEntity.error("参数异常");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.UNSUPPORTED_MEDIA_TYPE)) {
                return ResultEntity.error("请求头错误");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.INTERNAL_SERVER_ERROR)) {
                return ResultEntity.error("服务异常");
            }
            if (Objects.equals(e.getStatusCode(), HttpStatus.SERVICE_UNAVAILABLE)) {
                return ResultEntity.error("服务不存在");
            }
        }
        if (ExceptionUtil.isCausedBy(ex, BusinessException.class)) {
            log.error("发生业务异常", ex);
            return ResultEntity.error(ex.getMessage());
        }
        if (ExceptionUtil.isCausedBy(ex, BaseServiceErrorException.class)) {
            log.error("发生业务异常", ex);
            return ResultEntity.error(ex.getMessage());
        }
        log.error("系统发生异常错误", ex);
        return ResultEntity.SERVER_ERROR;
    }

    @ResponseBody
    @ExceptionHandler(value = MultipartException.class)
    public ResultEntity fileUploadExceptionHandler(MultipartException exception){
        return ResultEntity.error("上传失败！文件超过5个G");
    }
}
