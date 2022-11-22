package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkCamilleTarget;
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
public interface AppSharkCamilleTargetMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkCamilleTarget record);

    int insertSelective(AppSharkCamilleTarget record);

    AppSharkCamilleTarget selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkCamilleTarget record);

    int updateByPrimaryKey(AppSharkCamilleTarget record);

    int batchInsert(@Param("list") List<AppSharkCamilleTarget> list);

    List<AppSharkCamilleTarget> selectByVulnerId(@Param("id") Integer id);
}