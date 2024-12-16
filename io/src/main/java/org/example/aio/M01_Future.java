package org.example.aio;

import org.junit.Test;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M01_Future {

    /**
     * 主线程向线程池提交的三个任务同时开始执行，但是在使用get取结果的时候发现必须等耗时最长的任务结束之后才可以得到执行结果。
     * 也就是三个线程都结束后才返回主线程。
     * get方法阻塞了主线程，在取异步任务执行结果期间主线程不可以做其他事情，这不是真正的异步执行。
     * 但这个适合分开统计，合并汇总的场景。
     */
    @Test
    public void TestFuture() throws ExecutionException, InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ArrayList<Future<String>> futureList = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            final int finalI = i;
            Future<String> future = executor.submit(() -> {
                System.out.println("task["+ finalI +"] started!");
                Thread.sleep(1000*(3-finalI));// cost some time
                System.out.println("task["+ finalI +"]finished!");
                return "result["+ finalI +"]";
            });
            futureList.add(future);
        }

        for(Future<String> future : futureList) {
            System.out.println(future.get());
        }

        System.out.println("Main thread finished!");
        executor.shutdown();
    }

}
