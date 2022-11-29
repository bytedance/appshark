package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkTraversalSink;
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
public interface AppSharkTraversalSinkMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkTraversalSink record);

    int insertSelective(AppSharkTraversalSink record);

    AppSharkTraversalSink selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkTraversalSink record);

    int updateByPrimaryKey(AppSharkTraversalSink record);

    int batchInsert(@Param("list") List<AppSharkTraversalSink> list);

    List<AppSharkTraversalSink> selectListByVulnerId(@Param("vulnerId") Integer vulnerId);
}