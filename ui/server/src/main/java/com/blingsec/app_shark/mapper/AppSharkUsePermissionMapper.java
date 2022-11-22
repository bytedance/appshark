package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkUsePermission;
import java.util.List;

import com.blingsec.app_shark.pojo.qo.DetailPageConditon;
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
public interface AppSharkUsePermissionMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkUsePermission record);

    int insertSelective(AppSharkUsePermission record);

    AppSharkUsePermission selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkUsePermission record);

    int updateByPrimaryKey(AppSharkUsePermission record);

    int batchInsert(@Param("list") List<AppSharkUsePermission> list);

    List<AppSharkUsePermission> queryPermissionByPage(DetailPageConditon condition);

    String selectParaByName(@Param("permissionName") String permissionName);
}