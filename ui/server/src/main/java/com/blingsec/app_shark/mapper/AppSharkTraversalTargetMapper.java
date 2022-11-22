package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkTraversalTarget;
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
public interface AppSharkTraversalTargetMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkTraversalTarget record);

    int insertSelective(AppSharkTraversalTarget record);

    AppSharkTraversalTarget selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkTraversalTarget record);

    int updateByPrimaryKey(AppSharkTraversalTarget record);

    int batchInsert(@Param("list") List<AppSharkTraversalTarget> list);

    List<AppSharkTraversalTarget> selectListByVulnerId(@Param("vulnerId") Integer vulnerId);
}