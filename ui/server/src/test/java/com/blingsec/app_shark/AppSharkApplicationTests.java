package com.blingsec.app_shark;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDateTime;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.*;

@SpringBootTest
class AppSharkApplicationTests {
    @Autowired
    private ExecutorService executorService;

    @Test
    void contextLoads() {
        System.out.println(1111);
    }

    @Test
    void testTheardTimer(){
        Future<?> submit = executorService.submit(() -> {
            try {
                System.out.println("开始时间"+LocalDateTime.now());
                Thread.sleep(6000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                submit.cancel(true);
                System.out.println("结束时间"+LocalDateTime.now());
            }
        }, 2000);
    }

}
