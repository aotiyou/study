package org.example.juc.t_001;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author infosec
 * @since 2024/12/19
 */
public class T05_NewScheduledThreadPool {

    private static final Logger logger = LoggerFactory.getLogger(T05_NewScheduledThreadPool.class);

    public static void main(String[] args) {

        ScheduledExecutorService executorService = Executors.newScheduledThreadPool(1);

//        executorService.schedule(() -> {
//            logger.info("3秒后开始执行");
//        }, 3, TimeUnit.SECONDS);

//        executorService.scheduleAtFixedRate(() -> {
//            logger.info("3秒后开始执行，以后每2秒执行一次");
//        }, 3, 2, TimeUnit.SECONDS);
//
        executorService.scheduleWithFixedDelay(() -> {
            logger.info("3秒后开始执行，后续延迟2秒");
        }, 3, 2, TimeUnit.SECONDS);
    }

}
