package com.blingsec.app_shark.mapper;

import com.blingsec.app_shark.pojo.dto.FileInFo;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface FileInfoDao {

    int insertFileInfo(FileInFo fileInFo);

    List<FileInFo> findByIdIn(List<Integer> list);

    FileInFo findById(Long fileId);
}