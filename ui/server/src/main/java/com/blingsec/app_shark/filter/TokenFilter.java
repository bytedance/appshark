package com.blingsec.app_shark.filter;

import com.alibaba.fastjson.JSON;
import com.blingsec.app_shark.common.Constants;
import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.service.TokenValidService;
import com.blingsec.app_shark.util.GsonSingleton;
import com.google.common.collect.Lists;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@Order(1)
public class TokenFilter implements Filter {
    @Autowired
    private TokenValidService tokenValidService;

    private static final Gson gson = GsonSingleton.getInstance();
    private static final List<String> IGNORE_URI_LIST = Lists.newArrayList(
            // 普通登录
            "/login/normalLogin"
    );
    private static final List<String> TOKEN_WHITE_LIST = Lists.newArrayList(
            "6C552040-018C-11ED-AAD5-000EC66AF12D"
    );

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String token = request.getHeader(Constants.Auth.HEADER);
        String uriPath = request.getRequestURI();
        if (IGNORE_URI_LIST.contains(uriPath)) {
            chain.doFilter(request,response);
            return;
        }

        // 如果请求头不存在 返回未授权信息
        if (token == null) {
            //转换成JSON返回
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setHeader("Content-Type", "application/json;charset=UTF-8");
            response.getWriter().print(JSON.toJSONString(ResultEntity.UNAUTHORIZED));
            return;
        }
        if (TOKEN_WHITE_LIST.contains(token)) {
            log.info("特殊被放行的请求，请求地址为：{}", uriPath);
            chain.doFilter(request,response);
            return;
        }
        // 如果请求头存在，判断是否有效，有效的话，refresh令牌，无效的话，返回失败信息
        if (!tokenValidService.validateAndRefresh(token)) {
            //转换成JSON返回
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setHeader("Content-Type", "application/json;charset=UTF-8");
            response.getWriter().print(JSON.toJSONString(ResultEntity.UNAUTHORIZED));
            return;
        }
        chain.doFilter(request,response);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
