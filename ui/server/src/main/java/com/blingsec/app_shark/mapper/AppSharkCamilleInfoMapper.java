package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkCamilleInfo;
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
public interface AppSharkCamilleInfoMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkCamilleInfo record);

    int insertSelective(AppSharkCamilleInfo record);

    AppSharkCamilleInfo selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkCamilleInfo record);

    int updateByPrimaryKey(AppSharkCamilleInfo record);

    int batchInsert(@Param("list") List<AppSharkCamilleInfo> list);
}