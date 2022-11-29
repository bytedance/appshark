package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.entity.AppSharkCamilleVulner;
import java.util.List;

import com.blingsec.app_shark.pojo.qo.DetailPageConditon;
import com.blingsec.app_shark.pojo.vo.AppSharkCamilleVulnerVo;
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
public interface AppSharkCamilleVulnerMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppSharkCamilleVulner record);

    int insertSelective(AppSharkCamilleVulner record);

    AppSharkCamilleVulner selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppSharkCamilleVulner record);

    int updateByPrimaryKey(AppSharkCamilleVulner record);

    int batchInsert(@Param("list") List<AppSharkCamilleVulner> list);

    List<AppSharkCamilleVulnerVo> selectListByConditon(DetailPageConditon condition);
}