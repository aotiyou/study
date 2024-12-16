package org.example.aio;

import org.junit.Test;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M02_CompletionService {

    /**
     * 主线程向线程池提交的三个任务同时开始执行，与Future不同的是三个线程完成后分别返回主线程进行处理。
     * service.take().get()也会阻塞主线程。
     */
    @Test
    public void testCompletionService() throws InterruptedException, ExecutionException {

        ExecutorService executor = Executors.newFixedThreadPool(3);
        ExecutorCompletionService<String> service = new ExecutorCompletionService<>(executor);

        for (int i = 0; i < 3; i++) {
            int finalI = i;
            service.submit(() -> {
                System.out.println("task[" + finalI + "] started!");
                Thread.sleep(1000*3-finalI);// cost some time
                System.out.println("task[" + finalI + "] finished!");
                return "result[" + finalI + "]";
            });
        }

        for (int i = 0; i < 3; i++) {
            System.out.println(service.take().get());
        }

        System.out.println("Main thread finished!");
        executor.shutdown();

    }

}
