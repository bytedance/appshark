package com.blingsec.app_shark.pojo.vo;

import com.github.pagehelper.PageInfo;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.vo
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月25日 10:27
 * -------------- -------------- ---------------------
 */
@Data
public class AppSharkVulnerVo implements Serializable {
    /**漏洞总数**/
    private Long countVulner;
    /**漏洞占比**/
    private List<AppSharkVulnerRatio> appSharkVulnerRatioList;
    /**分页数据**/
    private PageInfo<AppSharkVulnerInfoVo> pageInfo;
}
