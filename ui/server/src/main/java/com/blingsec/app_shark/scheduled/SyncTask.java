package com.blingsec.app_shark.scheduled;

import com.blingsec.app_shark.service.AssignmentService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class SyncTask {
    @Autowired
    private AssignmentService assignmentService;

    @Scheduled(cron = "0 */10 * * * ?")
    public void syncData() {
        log.info("查询合规检测扫描是否有结果");
        assignmentService.syncData();
        log.info("执行结束");
    }
}
