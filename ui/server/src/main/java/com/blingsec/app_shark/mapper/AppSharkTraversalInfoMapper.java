package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkTraversalInfo;
import java.util.List;

import com.blingsec.app_shark.pojo.qo.DetailPageConditon;
import com.blingsec.app_shark.pojo.vo.AppSharkVulnerInfoVo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**  
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.mapper
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月19日 14:04
 * -------------- -------------- ---------------------
 */
@Mapper
public interface AppSharkTraversalInfoMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkTraversalInfo record);

    int insertSelective(AppSharkTraversalInfo record);

    AppSharkTraversalInfo selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkTraversalInfo record);

    int updateByPrimaryKey(AppSharkTraversalInfo record);

    int batchInsert(@Param("list") List<AppSharkTraversalInfo> list);

    List<AppSharkVulnerInfoVo> queryVulnerByPage(DetailPageConditon condition);
}