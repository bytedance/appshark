package com.blingsec.app_shark.service.impl;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.blingsec.app_shark.common.enums.AssignmentProcessStatus;
import com.blingsec.app_shark.common.enums.IsFlag;
import com.blingsec.app_shark.common.enums.UidTypeEnum;
import com.blingsec.app_shark.common.enums.VulnerLevelEnum;
import com.blingsec.app_shark.common.exception.BusinessException;
import com.blingsec.app_shark.mapper.*;
import com.blingsec.app_shark.pojo.ConfigJson;
import com.blingsec.app_shark.pojo.dto.AppInfo;
import com.blingsec.app_shark.pojo.dto.FileDto;
import com.blingsec.app_shark.pojo.dto.FileInFo;
import com.blingsec.app_shark.pojo.entity.*;
import com.blingsec.app_shark.pojo.qo.AssignmentCondition;
import com.blingsec.app_shark.pojo.qo.DetailPageConditon;
import com.blingsec.app_shark.pojo.vo.*;
import com.blingsec.app_shark.service.*;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.utils.Lists;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.service.impl
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月13日 18:06
 * -------------- -------------- ---------------------
 */
@Slf4j
@Service
@Transactional(readOnly = true)
public class AssignmentServiceImpl implements AssignmentService {
    private static final Integer ID_LENGTH = 10;
    @Autowired
    private UidService uidService;
    @Autowired
    private AssignmentDao assignmentDao;
    @Autowired
    private RedisService redisService;
    @Autowired
    private AppSharkAppInfoMapper appSharkAppInfoMapper;
    @Autowired
    private AppSharkCamilleInfoMapper appSharkCamilleInfoMapper;
    @Autowired
    private AppSharkCamilleVulnerMapper appSharkCamilleVulnerMapper;
    @Autowired
    private AppSharkCamilleTargetMapper appSharkCamilleTargetMapper;
    @Autowired
    private AppSharkTraversalInfoMapper appSharkTraversalInfoMapper;
    @Autowired
    private AppSharkTraversalVulnerMapper appSharkTraversalVulnerMapper;
    @Autowired
    private AppSharkTraversalSinkMapper appSharkTraversalSinkMapper;
    @Autowired
    private AppSharkTraversalSourceMapper appSharkTraversalSourceMapper;
    @Autowired
    private AppSharkTraversalTargetMapper appSharkTraversalTargetMapper;
    @Autowired
    private AppSharkUsePermissionMapper appSharkUsePermissionMapper;
    @Autowired
    private AppSharkService appSharkService;
    @Autowired
    private FileInfoService fileInfoService;
    @Autowired
    private ExecutorService executorService;

    /**
     * @Author renxin
     * @param assignmentDetailVo
     * @return java.lang.String
     * @Description 新增扫描任务
     * @creat_date 2022年10月17日
     * @creat_time 11:25:35
     */
    @Override
    @Transactional
    public String save(AssignmentDetailVo assignmentDetailVo) {
        String guid = uidService.getAndIncrementUid(UidTypeEnum.RWID, ID_LENGTH);
        assignmentDetailVo.setGuid(guid);
        assignmentDetailVo.setRules(assignmentDetailVo.getPreRules().stream().map(String::valueOf).collect(Collectors.joining(",")));;
        //首先判断任务列表中是否有进行中的
        int countProcessStatus = assignmentDao.countProcessStatus(AssignmentProcessStatus.PROCESSING);
        if (countProcessStatus == 0){
            assignmentDetailVo.setScanTime(new Date());
            assignmentDetailVo.setAssignmentProcessStatus(AssignmentProcessStatus.PROCESSING);
            this.saveScan(assignmentDetailVo);
        }else {
            assignmentDetailVo.setAssignmentProcessStatus(AssignmentProcessStatus.WAITING);
        }
        assignmentDao.insert(assignmentDetailVo);
        return guid;
    }

    /**
     * @Author renxin
     * @param assignmentDetailVo
     * @return void
     * @Description 向appShark发起扫描
     * @creat_date 2022年10月18日
     * @creat_time 15:23:19
     */
    @Transactional
    void saveScan(AssignmentDetailVo assignmentDetailVo) {
        String guid = assignmentDetailVo.getGuid();
        //获取文件信息
        FileInFo fileInFo = fileInfoService.findById(assignmentDetailVo.getAppAttachId());
        if (Objects.isNull(fileInFo)){
            throw new BusinessException("该Apk不存在!");
        }
        ConfigJson config = new ConfigJson();
        config.setFileName(fileInFo.getFileNameOld());
        config.setRules(assignmentDetailVo.getRules());
        config.setJobId(guid);
        config.setOut(guid);
        Integer largestAnalysis = assignmentDetailVo.getLargestAnalysis();
        if (Objects.isNull(largestAnalysis)){
            largestAnalysis = 600;
        }else if (largestAnalysis > 1296000){
            throw new BusinessException("最大点分析时间不可大于15天！");
        }
        config.setMaxPointerAnalyzeTime(largestAnalysis);
        //并向appShark发起扫描申请
        executorService.submit(() -> {
            try {
                appSharkService.saveScan(config,assignmentDetailVo);
            } catch (RuntimeException e){
                log.error("向appShark发起扫描异常！ 任务编号为：" + guid);
                log.error(e.getMessage());
                assignmentDetailVo.setAssignmentProcessStatus(AssignmentProcessStatus.ERROR);
                assignmentDao.updateAssignmentByGuid(assignmentDetailVo);
                scanNextAssignment();
                throw new BusinessException("向appShark发起扫描失败！");
            } catch (Exception e) {
                log.error("向appShark发起扫描异常！ 任务编号为：" + guid);
                log.error(e.getMessage());
            }
        });
    }

    /**
     * @Author renxin
     * @param condition
     * @return com.github.pagehelper.PageInfo<com.blingsec.app_shark.pojo.vo.AssignmentPageVo>
     * @Description 任务列表分页查询
     * @creat_date 2022年10月17日
     * @creat_time 11:25:21
     */
    @Override
    public PageInfo<AssignmentPageVo> queryByPage(AssignmentCondition condition) {
        String orderBy = condition.getOrderBy();
        if (StringUtils.isNotBlank(orderBy)) {
            PageHelper.orderBy("pts." + StrUtil.toUnderlineCase(orderBy));
        } else {
            PageHelper.orderBy("pts.created_at desc");
        }
        PageHelper.startPage(condition.getPage(), condition.getRows());
        List<AssignmentPageVo> list = assignmentDao.queryByPage(condition);
        return new PageInfo<>(Optional.ofNullable(list).orElse(new ArrayList<>()));
    }

    /**
     * @Author renxin
     * @param ids
     * @return int
     * @Description 任务删除
     * @creat_date 2022年10月17日
     * @creat_time 15:56:19
     */
    @Override
    @Transactional
    public int remove(List<Integer> ids) {
        //首先判断要删除的列表中是否有进行中的任务
        AssignmentCondition assignmentCondition = new AssignmentCondition();
        assignmentCondition.setAssignmentProcessStatus(AssignmentProcessStatus.PROCESSING);
        assignmentCondition.setIds(ids);
        List<AssignmentPageVo> list = assignmentDao.queryByPage(assignmentCondition);
        if (CollectionUtil.isNotEmpty(list)){
            log.error("失败！进行中状态的任务不支持删除！");
            throw new BusinessException("失败！进行中状态的任务不支持删除！");
        }
        return assignmentDao.deleteByIds(ids);
    }

    @Override
    @Transactional
    public void syncData() {
        //首先判断要删除的列表中是否有进行中的任务
        AssignmentCondition assignmentCondition = new AssignmentCondition();
        assignmentCondition.setAssignmentProcessStatus(AssignmentProcessStatus.PROCESSING);
        List<AssignmentPageVo> list = assignmentDao.queryByPage(assignmentCondition);
        //没有进行中的则不做处理
        if (CollectionUtil.isEmpty(list)){
            return;
        }
        //有进行中的则进行查询是否有扫描结果
        AssignmentPageVo assignmentPageVo = list.get(0);
        Integer assignmentId = assignmentPageVo.getId();
        String guid = assignmentPageVo.getGuid();
        String result = appSharkService.getResult(guid);
        if (StringUtils.isBlank(result)){
            log.info("扫描还未完成");
            return;
        }
        if (Objects.equals(assignmentPageVo.getAnalysisStatus(), IsFlag.YES)){
            log.info("扫描结果解析中...");
            return;
        }
        AssignmentDetailVo assignmentDetailVo = new AssignmentDetailVo();
        assignmentDetailVo.setId(assignmentId);
        assignmentDetailVo.setAnalysisStatus(IsFlag.YES);
        assignmentDetailVo.setResultJson(result);
        //先修改任务为解析中状态，并将结果json存到数据库
        assignmentDao.updateByPrimaryKeySelective(assignmentDetailVo);
        assignmentDao.insertResultJson(assignmentDetailVo);
//        executorService.submit(() -> {
            //扫描结果不为空时，则说明已完成，封装返回数据并进行任务状态的修改
            this.populateResult(result,assignmentId);
            //解析结束后修改此任务为检测成功状态
            assignmentDetailVo.setAssignmentProcessStatus(AssignmentProcessStatus.FINISHED);
            assignmentDao.updateByPrimaryKeySelective(assignmentDetailVo);
            //发起下一个未开始的任务进行扫描
            scanNextAssignment();
//        });
    }

    @Override
    @Transactional
    public void scanNextAssignment() {
        AssignmentCondition condition = new AssignmentCondition();
        condition.setAssignmentProcessStatus(AssignmentProcessStatus.WAITING);
        List<AssignmentPageVo> assignmentPageVos = assignmentDao.queryByPage(condition);
        if (CollectionUtil.isNotEmpty(assignmentPageVos)){
            AssignmentPageVo assignmentPageVo1 = assignmentPageVos.get(0);
            AssignmentDetailVo assignmentDetailVo1 = new AssignmentDetailVo();
            BeanUtils.copyProperties(assignmentPageVo1,assignmentDetailVo1);
            assignmentDetailVo1.setAppAttachId(assignmentPageVo1.getAppAttach().getFileId());
            this.saveScan(assignmentDetailVo1);
            assignmentDetailVo1.setScanTime(new Date());
            assignmentDetailVo1.setAssignmentProcessStatus(AssignmentProcessStatus.PROCESSING);
            assignmentDao.updateByPrimaryKeySelective(assignmentDetailVo1);
        }
    }

    /**
     * @Author renxin
     * @param id
     * @return com.blingsec.app_shark.pojo.vo.AssignmentDetailVo
     * @Description 任务详情查看
     * @creat_date 2022年10月21日
     * @creat_time 14:04:58
     */
    @Override
    public AssignmentDetailVo detail(Integer id) {
        AssignmentDetailVo detail = assignmentDao.findById(id);
        if (Objects.isNull(detail)) {
            return null;
        }
        //封装app信息
        Long appAttachId = detail.getAppAttachId();
        FileInFo fileInFo = fileInfoService.findById(appAttachId);
            if (Objects.nonNull(fileInFo)){
                FileDto filedDto = new FileDto();
                filedDto.setFileId(appAttachId);
                filedDto.setFileName(fileInFo.getFileNameOld());
                filedDto.setFileUrl(fileInFo.getFileStorgePath());
                filedDto.setFileNameNew(fileInFo.getFileNameNew());
                detail.setAppAttach(filedDto);
            }
        return detail;
    }

    /**
     * @Author renxin
     * @param condition
     * @return com.github.pagehelper.PageInfo<com.blingsec.app_shark.pojo.entity.AppSharkUsePermission>
     * @Description 任务详情权限清单分页查询
     * @creat_date 2022年10月25日
     * @creat_time 10:21:37
     */
    @Override
    public PageInfo<AppSharkUsePermission> queryPermissionByPage(DetailPageConditon condition) {
        String orderBy = condition.getOrderBy();
        if (StringUtils.isNotBlank(orderBy)) {
            PageHelper.orderBy(StrUtil.toUnderlineCase(orderBy));
        } else {
            PageHelper.orderBy("type");
        }
        PageHelper.startPage(condition.getPage(), condition.getRows());
        List<AppSharkUsePermission> list = appSharkUsePermissionMapper.queryPermissionByPage(condition);
        return new PageInfo<>(Optional.ofNullable(list).orElse(new ArrayList<>()));
    }

    @Override
    public PageInfo<AppSharkVulnerInfoVo> queryVulnerByPage(DetailPageConditon condition) {
        //1.分页查询漏洞信息
        String orderBy = condition.getOrderBy();
        if (StringUtils.isNotBlank(orderBy)) {
            PageHelper.orderBy(StrUtil.toUnderlineCase(orderBy));
        } else {
            PageHelper.orderBy("astv.created_at desc");
        }
        PageHelper.startPage(condition.getPage(), condition.getRows());
        List<AppSharkVulnerInfoVo> list = appSharkTraversalInfoMapper.queryVulnerByPage(condition);
        PageInfo<AppSharkVulnerInfoVo> appSharkVulnerInfoVoPageInfo = new PageInfo<>(Optional.ofNullable(list).orElse(new ArrayList<>()));
        //2.漏洞不为空时遍历填充详情信息
        list.forEach(appSharkVulnerInfoVo -> {
            Integer vulnerId = appSharkVulnerInfoVo.getAppSharkTraversalVulner().getId();
            List<AppSharkTraversalSink> appSharkTraversalSinks = appSharkTraversalSinkMapper.selectListByVulnerId(vulnerId);
            if (CollectionUtil.isNotEmpty(appSharkTraversalSinks)){
                appSharkVulnerInfoVo.setAppSharkTraversalSinks(appSharkTraversalSinks);
            }
            List<AppSharkTraversalSource> appSharkTraversalSources = appSharkTraversalSourceMapper.selectListByVulnerId(vulnerId);
            if (CollectionUtil.isNotEmpty(appSharkTraversalSources)){
                appSharkVulnerInfoVo.setAppSharkTraversalSources(appSharkTraversalSources);
            }
            List<AppSharkTraversalTarget> appSharkTraversalTargets = appSharkTraversalTargetMapper.selectListByVulnerId(vulnerId);
            if (CollectionUtil.isNotEmpty(appSharkTraversalTargets)){
                appSharkVulnerInfoVo.setAppSharkTraversalTargets(appSharkTraversalTargets);
            }
        });
        return appSharkVulnerInfoVoPageInfo;
    }

    /**
     * 查询合规检测行为分类
     * @param id
     * @return
     */
    @Override
    public Map<? extends Object, Object> queryCamilleMap(Integer id) {
        DetailPageConditon condition = new DetailPageConditon();
        condition.setAssessmentId(id);
        List<AppSharkCamilleVulnerVo> appSharkCamilleVulnerList = appSharkCamilleVulnerMapper.selectListByConditon(condition);
        if(CollectionUtil.isEmpty(appSharkCamilleVulnerList)){
            return new HashMap<>();
        }
        //当map不为空时则判断数量是否大于16，大于16时后面的key都为其他
        Map<String, Long> collect1 = appSharkCamilleVulnerList.stream().collect(Collectors.groupingBy(AppSharkCamilleVulnerVo::getName, Collectors.counting()));
        HashMap<String, Object> stringLongHashMap = Maps.newLinkedHashMap(collect1);
        Set<String> camilleTypes = collect1.keySet();
        int camillesSize = camilleTypes.size();
        //列表上展示的16个  包括其他
        Map<String, Object> camilleAllType = Maps.newLinkedHashMap();
        if (camillesSize == 0 ){
            return stringLongHashMap;
        } else if (camillesSize > 16){
            //其他选项里的key值
            Map<String, Object> camilleOtherType = Maps.newLinkedHashMap();
            var ref = new Object() {
                int i = 1;
            };
            AtomicReference<Long> otherValue = new AtomicReference<>(0L);
            camilleTypes.forEach(key->{
                Long finalValue = collect1.get(key);
                if (ref.i <=15){
                    camilleAllType.put(key,finalValue.toString());
                }else {
                    otherValue.updateAndGet(v -> v + finalValue);
                    camilleOtherType.put(key,finalValue.toString());
                }
                ref.i++;
            });
            camilleAllType.put("其他",otherValue.get().toString());
            redisService.hSetAll("CamilleOtherType_" + id,camilleOtherType);
            return camilleAllType;
        }else {
            camilleTypes.forEach(key->{
                Long finalValue = collect1.get(key);
                camilleAllType.put(key,finalValue.toString());
            });
        }
        return camilleAllType;
    }

    @Override
    public PageInfo<AppSharkCamilleVulnerVo> queryComplianceByPage(DetailPageConditon condition) {
        //先判断行为列表中是否包含其他，若包含则取redis中
        List<String> vulnerNames = condition.getVulnerNames();
        Integer assessmentId = condition.getAssessmentId();
        if (CollectionUtil.isNotEmpty(vulnerNames) && vulnerNames.contains("其他")){
            vulnerNames.remove("其他");
            Map<Object, Object> otherTypes = redisService.hGetAll("CamilleOtherType_" + assessmentId);
            otherTypes.entrySet().forEach((entry) -> {
                vulnerNames.add(entry.getKey().toString());
            });
            condition.setVulnerNames(vulnerNames);
        }
        String orderBy = condition.getOrderBy();
        if (StringUtils.isNotBlank(orderBy)) {
            PageHelper.orderBy(StrUtil.toUnderlineCase(orderBy));
        } else {
            PageHelper.orderBy("name");
        }
        PageHelper.startPage(condition.getPage(), condition.getRows());
        List<AppSharkCamilleVulnerVo> appSharkCamilleVulnerList = appSharkCamilleVulnerMapper.selectListByConditon(condition);
        //遍历封装文件信息
        if (CollectionUtil.isNotEmpty(appSharkCamilleVulnerList)){
            //遍历填充堆栈信息
            appSharkCamilleVulnerList.forEach(appSharkCamilleVulner -> {
                List<AppSharkCamilleTarget> appSharkCamilleTargets = appSharkCamilleTargetMapper.selectByVulnerId(appSharkCamilleVulner.getId());
                if (CollectionUtil.isNotEmpty(appSharkCamilleTargets)){
                    appSharkCamilleVulner.setTargets(appSharkCamilleTargets.stream().map(AppSharkCamilleTarget::getTarget).collect(Collectors.toList()));
                }
            });
        }
        return new PageInfo<>(Optional.ofNullable(appSharkCamilleVulnerList).orElse(new ArrayList<>()));
    }

    @Override
    public AppSharkVulnerVo statisticsType(DetailPageConditon condition) {
        AppSharkVulnerVo appSharkVulnerVo = new AppSharkVulnerVo();
        List<AppSharkVulnerInfoVo> list = appSharkTraversalInfoMapper.queryVulnerByPage(condition);
        long total = list.size();
        appSharkVulnerVo.setCountVulner(total);
        //3.填充统计比例
        List<AppSharkVulnerRatio> appSharkVulnerRatioList = Lists.newArrayList();
        Map<String, List<AppSharkVulnerInfoVo>> collect = list.stream().collect(Collectors.groupingBy(AppSharkVulnerInfoVo::getModel));
        VulnerLevelEnum[] values = VulnerLevelEnum.values();
        for (int i = 0; i < values.length; i++){
            String name = values[i].getName();
            AppSharkVulnerRatio appSharkVulnerRatio = new AppSharkVulnerRatio();
            appSharkVulnerRatio.setModel(name);
            List<AppSharkVulnerInfoVo> appSharkVulnerInfoVos = collect.get(name);
            if (CollectionUtil.isEmpty(appSharkVulnerInfoVos)){
                appSharkVulnerRatio.setCountVulner(0);
                appSharkVulnerRatio.setVulnerRatio("0%");
            }else {
                int size = appSharkVulnerInfoVos.size();
                appSharkVulnerRatio.setCountVulner(size);
                appSharkVulnerRatio.setVulnerRatio(NumberUtil.formatPercent(size / (double) total, 0));
            }
            appSharkVulnerRatioList.add(appSharkVulnerRatio);
        }
        appSharkVulnerVo.setAppSharkVulnerRatioList(appSharkVulnerRatioList);
        return appSharkVulnerVo;


    }

    private void populateResult(String result, Integer assignmentId) {
        //对result.json逐层解析，存入数据库
        JSONObject jsonObject = JSONObject.parseObject(result);
        //1.封装App基本信息
        AppSharkAppInfo appSharkAppInfo = new AppSharkAppInfo();
        AppInfo appInfo = jsonObject.getObject("AppInfo",AppInfo.class);
        if (Objects.isNull(appInfo)){
            log.error("App基本信息为空");
            return;
        }
        BeanUtils.copyProperties(appInfo,appSharkAppInfo);
        appSharkAppInfo.setAssignmentId(assignmentId);
        appSharkAppInfoMapper.insertSelective(appSharkAppInfo);
        //2.封装权限信息
        List<AppSharkUsePermission> appSharkUsePermissionList = Lists.newArrayList();
        Set<String> permissionNames = Sets.newHashSet();
        List<String> usePermissions = (List<String>) jsonObject.get("UsePermissions");
        if (CollectionUtil.isNotEmpty(usePermissions)){
            usePermissions.forEach(usePermission -> {
                String[] split = usePermission.split("permission.");
                if (split.length == 2){
                    permissionNames.add(split[1]);
                }
            });
        }
        Map<String, String> definePermissions = (Map<String, String>) jsonObject.get("DefinePermissions");
        if (CollectionUtil.isNotEmpty(definePermissions)){
            definePermissions.keySet().forEach(key -> {
                String[] split = key.split("permission.");
                if (split.length == 2){
                    permissionNames.add(split[1]);
                }
            });
        }
        //权限名称去重，查询对应的释义进行批量添加
        if (CollectionUtil.isNotEmpty(permissionNames)) {
            permissionNames.forEach(permissionName -> {
                AppSharkUsePermission appSharkUsePermission = new AppSharkUsePermission();
                appSharkUsePermission.setAssignmentId(assignmentId);
                appSharkUsePermission.setName(permissionName);
                String para = appSharkUsePermissionMapper.selectParaByName(permissionName);
                if (Strings.isNotBlank(para)){
                    appSharkUsePermission.setParaphrase(para);
                }else {
                    appSharkUsePermission.setParaphrase("--");
                }
                appSharkUsePermissionList.add(appSharkUsePermission);
            });
            appSharkUsePermissionMapper.batchInsert(appSharkUsePermissionList);
        }

        JSONObject securityInfo = jsonObject.getJSONObject("SecurityInfo");
        if (Objects.isNull(securityInfo)){
            log.error("SecurityInfo基本信息为空");
            return;
        }
        //获取安全信息所有key
        Set<String> securityKeys = securityInfo.keySet();
        if(CollectionUtil.isNotEmpty(securityKeys)){
            Iterator<String> iterator = securityKeys.stream().iterator();
            for (int i = 0;i < securityKeys.size();i++){
                String securityKey = iterator.next();
                JSONObject securityValue = securityInfo.getJSONObject(securityKey);
                if (Objects.isNull(securityValue)){
                    continue;
                }
                switch (securityKey){
                    //3.封装合规检测信息
                    //合规检测的四种类型
                    case "camille":
                    case "serial_Log":
                    case "MAC":
                    case "IMEI_SendBroadcast":
                    //获取所有合规检测实体的key
                        Set<String> camilles = securityValue.keySet();
                        if (CollectionUtil.isNotEmpty(camilles)){
                            camilles.stream().forEach(camilleKey->{
                                //遍历合规，封装合规检测基本信息
                                JSONObject camilleKey1 = securityValue.getJSONObject(camilleKey);
                                AppSharkCamilleInfo appSharkCamilleInfo = new AppSharkCamilleInfo();
                                appSharkCamilleInfo.setAssignmentId(assignmentId);
                                appSharkCamilleInfo.setCategory(this.judgeBlank(camilleKey1.getString("category")));
                                appSharkCamilleInfo.setDetail(this.judgeBlank(camilleKey1.getString("detail")));
                                appSharkCamilleInfo.setName(this.judgeBlank(camilleKey1.getString("name")));
                                appSharkCamilleInfoMapper.insertSelective(appSharkCamilleInfo);
                                Integer camilleInfoId = appSharkCamilleInfo.getId();
                                //获取堆栈，位置信息列表
                                JSONArray vulners = camilleKey1.getJSONArray("vulners");
                                if (vulners.size() > 0){
                                    for (int j = 0; j < vulners.size(); j++) {
                                        JSONObject vulner = vulners.getJSONObject(j);
                                        //遍历合规信息
                                        JSONObject details = vulner.getJSONObject("details");
                                        if (Objects.nonNull(details)) {
                                            AppSharkCamilleVulner appSharkCamilleVulner = new AppSharkCamilleVulner();
                                            appSharkCamilleVulner.setAssignmentId(assignmentId);
                                            appSharkCamilleVulner.setUrl(this.judgeBlank(details.getString("url")));
                                            appSharkCamilleVulner.setPosition(this.judgeBlank(details.getString("position")));
                                            appSharkCamilleVulner.setCamilleInfoId(camilleInfoId);
                                            appSharkCamilleVulnerMapper.insertSelective(appSharkCamilleVulner);
                                            Integer appSharkCamilleVulnerId = appSharkCamilleVulner.getId();
                                            //封装堆栈信息
                                            List<String> targets = (List<String>) details.get("target");
                                            if(CollectionUtil.isNotEmpty(targets)){
                                                List<AppSharkCamilleTarget> appSharkCamilleTargets = Lists.newArrayList();
                                                targets.forEach(target->{
                                                    appSharkCamilleTargets.add(new AppSharkCamilleTarget(appSharkCamilleVulnerId,target));
                                                });
                                                appSharkCamilleTargetMapper.batchInsert(appSharkCamilleTargets);
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        break;
                    //4.封装漏洞信息
                    //安全漏洞规则
                    case "Provider":
                        JSONObject contentProviderPathTraversal = securityValue.getJSONObject("ContentProviderPathTraversal");
                        this.populateTraversal(contentProviderPathTraversal,assignmentId);
                        break;
                    case "PendingIntent":
                        JSONObject PendingIntentMutable = securityValue.getJSONObject("PendingIntentMutable");
                        this.populateTraversal(PendingIntentMutable,assignmentId);
                        break;
                    case "FileRisk":
                        JSONObject unZipSlip = securityValue.getJSONObject("unZipSlip");
                        this.populateTraversal(unZipSlip,assignmentId);
                        break;
                    case "IntentRedirection":
                        JSONObject IntentRedirectionBabyVersion = securityValue.getJSONObject("IntentRedirectionBabyVersion");
                        this.populateTraversal(IntentRedirectionBabyVersion,assignmentId);
                        break;
                }
            }
        }
    }

    private void populateTraversal(JSONObject contentProviderPathTraversal, Integer assignmentId) {
        if(Objects.nonNull(contentProviderPathTraversal)){
            AppSharkTraversalInfo appSharkTraversalInfo = new AppSharkTraversalInfo();
            appSharkTraversalInfo.setAssignmentId(assignmentId);
            appSharkTraversalInfo.setCategory(this.judgeBlank(contentProviderPathTraversal.getString("category")));
            String model = contentProviderPathTraversal.getString("model");
            appSharkTraversalInfo.setModel(StringUtils.isNotBlank(model) ? model : "other");
            appSharkTraversalInfo.setName(this.judgeBlank(contentProviderPathTraversal.getString("name")));
            appSharkTraversalInfo.setDetail(this.judgeBlank(contentProviderPathTraversal.getString("detail")));
            appSharkTraversalInfoMapper.insertSelective(appSharkTraversalInfo);
            Integer appSharkTraversalInfoId = appSharkTraversalInfo.getId();
            //循环漏洞详情进行封装
            JSONArray vulners = contentProviderPathTraversal.getJSONArray("vulners");
            if (vulners.size() > 0){
                for (int i = 0; i < vulners.size(); i++){
                    JSONObject vulner = vulners.getJSONObject(i);
                    if (Objects.nonNull(vulner)){
                        JSONObject details = vulner.getJSONObject("details");
                        if (Objects.nonNull(details)){
                            AppSharkTraversalVulner appSharkTraversalVulner = new AppSharkTraversalVulner();
                            appSharkTraversalVulner.setAssignmentId(assignmentId);
                            appSharkTraversalVulner.setPosition(this.judgeBlank(details.getString("position")));
                            appSharkTraversalVulner.setUrl(this.judgeBlank(details.getString("url")));
                            appSharkTraversalVulner.setEntryMethod(this.judgeBlank(details.getString("entryMethod")));
                            appSharkTraversalVulner.setTraversalInfoId(appSharkTraversalInfoId);
                            appSharkTraversalVulnerMapper.insertSelective(appSharkTraversalVulner);
                            Integer appSharkTraversalVulnerId = appSharkTraversalVulner.getId();
                            //封装起点，重点路径以及入口
                            List<String> sinks = (List<String>) details.get("Sink");
                            if (CollectionUtil.isNotEmpty(sinks)){
                                List<AppSharkTraversalSink> appSharkTraversalSinks = Lists.newArrayList();
                                sinks.forEach(sink->{
                                    appSharkTraversalSinks.add(new AppSharkTraversalSink(appSharkTraversalVulnerId,sink));
                                });
                                appSharkTraversalSinkMapper.batchInsert(appSharkTraversalSinks);
                            }

                            List<String> sources = (List<String>) details.get("Source");
                            if (CollectionUtil.isNotEmpty(sources)){
                                List<AppSharkTraversalSource> appSharkTraversalSources = Lists.newArrayList();
                                sinks.forEach(sink->{
                                    appSharkTraversalSources.add(new AppSharkTraversalSource(appSharkTraversalVulnerId,sink));
                                });
                                appSharkTraversalSourceMapper.batchInsert(appSharkTraversalSources);
                            }

                            List<String> targets = (List<String>) details.get("target");
                            if (CollectionUtil.isNotEmpty(targets)){
                                List<AppSharkTraversalTarget> appSharkTraversalTargets = Lists.newArrayList();
                                sinks.forEach(sink->{
                                    appSharkTraversalTargets.add(new AppSharkTraversalTarget(appSharkTraversalVulnerId,sink));
                                });
                                appSharkTraversalTargetMapper.batchInsert(appSharkTraversalTargets);
                            }
                        }
                    }
                }
            }
        }
    }

    private String judgeBlank(String value) {
        if(StringUtils.isBlank(value)){
            return "-";
        }else {
            return value;
        }
    }
}
