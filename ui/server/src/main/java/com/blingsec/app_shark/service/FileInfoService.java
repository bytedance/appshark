package com.blingsec.app_shark.service;


import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.pojo.dto.FileDto;
import com.blingsec.app_shark.pojo.dto.FileInFo;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.util.List;


public interface FileInfoService {
    ResultEntity saveUploadFile(MultipartFile file, String rootPath, String fileDir, boolean isRules);

    ResultEntity getDownLoad(HttpServletRequest request, HttpServletResponse response, String fileName, File file);

    /**
     * 根据file id list 查询文件详细信息
     */
    List<FileDto> findByIdIn(List<Integer> list);

    FileInFo findById(Long fileId);

    ResultEntity uploadApp(MultipartFile file, String rootPath, String fileDir);
}
