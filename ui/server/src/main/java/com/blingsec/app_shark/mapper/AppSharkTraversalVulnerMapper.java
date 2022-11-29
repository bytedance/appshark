package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkTraversalVulner;
import java.util.List;
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
public interface AppSharkTraversalVulnerMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkTraversalVulner record);

    int insertSelective(AppSharkTraversalVulner record);

    AppSharkTraversalVulner selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkTraversalVulner record);

    int updateByPrimaryKey(AppSharkTraversalVulner record);

    int batchInsert(@Param("list") List<AppSharkTraversalVulner> list);
}