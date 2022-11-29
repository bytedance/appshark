package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkTraversalSource;
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
public interface AppSharkTraversalSourceMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkTraversalSource record);

    int insertSelective(AppSharkTraversalSource record);

    AppSharkTraversalSource selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkTraversalSource record);

    int updateByPrimaryKey(AppSharkTraversalSource record);

    int batchInsert(@Param("list") List<AppSharkTraversalSource> list);

    List<AppSharkTraversalSource> selectListByVulnerId(@Param("vulnerId") Integer vulnerId);
}