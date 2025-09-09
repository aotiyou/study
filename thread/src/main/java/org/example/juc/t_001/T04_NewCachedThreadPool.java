package org.example.juc.t_001;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author infosec
 * @since 2024/12/19
 */
public class T04_NewCachedThreadPool {

    private final static Logger logger = LoggerFactory.getLogger(T04_NewCachedThreadPool.class);

    public static void main(String[] args) {
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < 5; i++) {
            int groupId = i;

            executorService.execute(() -> {
                for (int j = 0; j < 5; j++) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {

                    }
                    logger.info("第 {} 组任务，第 {} 次执行完成", groupId, j);
                }
            });
        }

        executorService.shutdown();
    }

}
