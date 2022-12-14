package com.blingsec.app_shark.service.impl;


import cn.hutool.crypto.SecureUtil;
import com.blingsec.app_shark.common.exception.BusinessException;
import com.blingsec.app_shark.mapper.FileInfoDao;
import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.pojo.dto.FileDto;
import com.blingsec.app_shark.pojo.dto.FileInFo;
import com.blingsec.app_shark.service.FileInfoService;
import com.google.common.collect.Lists;
import org.apache.commons.lang.StringUtils;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.apache.tomcat.util.http.fileupload.util.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Service
public class FileInfoServiceImpl implements FileInfoService {
    @Autowired
    private FileInfoDao fileInfoDao;
    public static final String JSON = "json";
    private static final List<String> WHITE_LIST = Lists.newArrayList(
            "xls",
            "xlsm",
            "xltx",
            "xltm",
            JSON,
            "docx",
            "docm",
            "doc",
            "dotx",
            "dotm",
            "dot",
            "pdf",
            "xlsx",
            "xps",
            "mht",
            "mhtml",
            "htm",
            "html",
            "rtf",
            "txt",
            "xml",
            "ppt",
            "pptx",
            "tif",
            "jpg",
            "zip",
            "7z",
            "rar",
            "png",
            "apk",
            "ipa"
    );
    private static final Logger logger = LoggerFactory.getLogger(FileInfoServiceImpl.class);

    @Override
    public ResultEntity saveUploadFile(MultipartFile file, String rootPath, String fileDir, boolean isRules) {
        //??????????????????
        try {
            //??????????????????
            String originalFile = file.getOriginalFilename();
            if (originalFile == null) {
                return ResultEntity.error("??????????????????");
            }
            String originalFilename = new String(originalFile.getBytes(StandardCharsets.UTF_8));
            //??????.???????????????
            String beforeLast = StringUtils.substringBeforeLast(originalFilename, ".");
            //????????????????????????
            String beforeLastMd5 = SecureUtil.md5(beforeLast + System.currentTimeMillis());
            //?????????????????????
            String suffix = StringUtils.substringAfterLast(originalFilename, ".");
            if (!WHITE_LIST.contains(suffix)) {
                throw new BusinessException("????????????????????????");
            }
            if (isRules && !JSON.equals(suffix)) {
                throw new BusinessException("????????????????????????");
            }
            String fileNameNew = beforeLastMd5 + "." + suffix;
            if (isRules) {
                fileNameNew = originalFilename;
            }
            //???????????????--??????????????????
            String storagePath = rootPath + fileNameNew;
            logger.debug("??????????????????" + file.getName() + "," + file.getContentType() + "," + originalFilename
                    + "????????????????????????" + storagePath);
            Streams.copy(file.getInputStream(), new FileOutputStream(storagePath), true);
            //???????????????
            InputStream inputStream = file.getInputStream();
            FileOutputStream outputStream = new FileOutputStream(storagePath);
            IOUtils.copy(inputStream, outputStream);
            outputStream.close();
//            Path path = Paths.get(storagePath);
//            Files.write(path, file.getBytes());
            FileInFo fileInFo = new FileInFo();
            fileInFo.setFileType(file.getContentType());
            fileInFo.setFileNameOld(originalFilename);
            fileInFo.setFileNameNew(fileNameNew);
            fileInFo.setFileStorgePath(fileDir + fileNameNew);
            Date date = new Date();
            fileInFo.setCtime(date);
            fileInFo.setMtime(date);
            if (!isRules) {
                int saveResInt = fileInfoDao.insertFileInfo(fileInFo);

//            file = null;
//            System.gc();//????????????GC
                if (saveResInt > 0) {
                    return ResultEntity.success(fileInFo);
                } else {
                    return ResultEntity.FILE_INFO_UPLOAD;
                }
            } else {
                return ResultEntity.SUCCESS;
            }
        } catch (IOException e) {
            logger.debug("????????????---" + e);
            return ResultEntity.ERROR;
        }
    }

    @Override
    public ResultEntity getDownLoad(HttpServletRequest request, HttpServletResponse response, String fileName, File file) {
        //????????????????????????????????????force-download???????????????????????????????????????????????????????????????
        String type = request.getServletContext().getMimeType(fileName);
        response.setContentType(type);
        //???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
        response.addHeader("Content-Disposition", "attachment; filename=" + file.getName());
        try {
            org.apache.commons.io.IOUtils.copy(new FileInputStream(file), response.getOutputStream());
        } catch (IOException e) {
            logger.error("????????????????????????" + e);
            return ResultEntity.ERROR;
        }
        return null;
    }

    @Override
    public List<FileDto> findByIdIn(List<Integer> list) {
        List<FileInFo> files = fileInfoDao.findByIdIn(list);
        List<FileDto> result = Lists.newArrayList();
        for (FileInFo file : files) {
            FileDto dto = new FileDto();
            dto.setFileId(file.getFileId());
            dto.setFileName(file.getFileNameOld());
            dto.setFileUrl(file.getFileStorgePath());
            dto.setFileNameNew(file.getFileNameNew());
            result.add(dto);
        }
        return result;
    }

    @Override
    public FileInFo findById(Long fileId) {
        return fileInfoDao.findById(fileId);
    }

    @Override
    public ResultEntity uploadApp(MultipartFile file, String rootPath, String fileDir) {
        //??????????????????
        try {
            //??????????????????
            String originalFile = file.getOriginalFilename();
            if (originalFile == null) {
                return ResultEntity.error("??????????????????");
            }
            String originalFilename = new String(originalFile.getBytes(StandardCharsets.UTF_8));
            //??????.???????????????
            String beforeLast = StringUtils.substringBeforeLast(originalFilename, ".");
            //????????????????????????
            String beforeLastMd5 = SecureUtil.md5(beforeLast + System.currentTimeMillis());
            //?????????????????????
            String suffix = StringUtils.substringAfterLast(originalFilename, ".");
            if (!"apk".equals(suffix)) {
                throw new BusinessException("???????????????apk????????????");
            }
            String fileNameNew = beforeLastMd5 + "." + suffix;
            //???????????????--??????????????????
            String storagePath = rootPath + originalFilename;
            logger.debug("??????????????????" + file.getName() + "," + file.getContentType() + "," + originalFilename
                    + "????????????????????????" + storagePath);
            Streams.copy(file.getInputStream(), new FileOutputStream(storagePath), true);
            //???????????????
            InputStream inputStream = file.getInputStream();
            FileOutputStream outputStream = new FileOutputStream(storagePath);
            IOUtils.copy(inputStream, outputStream);
            outputStream.close();
//            Path path = Paths.get(storagePath);
//            Files.write(path, file.getBytes());
            FileInFo fileInFo = new FileInFo();
            fileInFo.setFileType(file.getContentType());
            fileInFo.setFileNameOld(originalFilename);
            fileInFo.setFileNameNew(fileNameNew);
            fileInFo.setFileStorgePath(fileDir + fileNameNew);
            Date date = new Date();
            fileInFo.setCtime(date);
            fileInFo.setMtime(date);
            int saveResInt = fileInfoDao.insertFileInfo(fileInFo);

//            file = null;
//            System.gc();//????????????GC
            if (saveResInt > 0) {
                return ResultEntity.success(fileInFo);
            } else {
                return ResultEntity.FILE_INFO_UPLOAD;
            }
        } catch (IOException e) {
            logger.debug("????????????---" + e);
            return ResultEntity.ERROR;
        }
    }
}
