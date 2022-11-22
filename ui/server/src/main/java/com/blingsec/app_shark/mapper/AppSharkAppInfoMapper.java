package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkAppInfo;
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
public interface AppSharkAppInfoMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkAppInfo record);

    int insertSelective(AppSharkAppInfo record);

    AppSharkAppInfo selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkAppInfo record);

    int updateByPrimaryKey(AppSharkAppInfo record);

    int batchInsert(@Param("list") List<AppSharkAppInfo> list);
}