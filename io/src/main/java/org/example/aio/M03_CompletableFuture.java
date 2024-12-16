package org.example.aio;

import org.junit.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M03_CompletableFuture {

    /**
     * 主线程向线程池提交的三个任务同时开始执行，主线程只负责提交任务，任务提交完后就可以做其他事情了，
     * 主线程提交任务时给了任务回调函数，任务执行完成后调用这个函数就行了。这才是真正的异步
     */
    @Test
    public void testCompletableFuture() {

        ExecutorService executor = Executors.newFixedThreadPool(3);
        for (int i = 0; i < 3; i++) {
            int finalI = i;
            CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
                System.out.println("task[" + finalI + "] started!");
                try {
                    Thread.sleep(1000 * 3 - finalI);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                System.out.println("task[" + finalI + "] finished!");
                return "result[" + finalI + "]";
            }, executor);

            future.thenAccept(System.out::println);
        }

        System.out.println("Main thread finished!");
        executor.shutdown();

    }

}
