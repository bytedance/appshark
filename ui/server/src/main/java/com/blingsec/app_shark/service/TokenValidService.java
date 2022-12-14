package com.blingsec.app_shark.service;

/**
 * @author wenhailin
 */
public interface TokenValidService {
    public void refresh(String token);

    public Boolean validate(String token);

    public Boolean validateAndRefresh(String token);
}
