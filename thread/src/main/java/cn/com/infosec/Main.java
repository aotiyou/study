package cn.com.infosec;

import com.google.common.util.concurrent.ThreadFactoryBuilder;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class Main {
    public static void main(String[] args) {
        ThreadFactory executeThreadFactory = new ThreadFactoryBuilder().setNameFormat("upgrade-pool-%d").build();
        ExecutorService poolExecutor = new ThreadPoolExecutor(1, 2, 2000L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>(10), executeThreadFactory, new ThreadPoolExecutor.AbortPolicy());
        FutureTask<String> future = new FutureTask<>(new Callable<String>() {
            @Override
            public String call() throws Exception { // 建议抛出异常
                try {
                    Thread.sleep(1 * 1000L);
                    System.out.println(1111);
                    return "success!";
                } catch (Exception e) {
                    throw new Exception("Callable terminated with Exception!"); // call方法可以抛出异常
                }
            }
        });
        poolExecutor.execute(future);
        poolExecutor.shutdown();
    }


}
