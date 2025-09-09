package org.example.juc.t_001;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author infosec
 * @since 2024/12/18
 */
public class T01_ThreadPoolTrader implements Executor {

    // 用于控制线程池的状态，包括线程池的活跃线程数
    private final AtomicInteger cti = new AtomicInteger(0);
    // 核心线程池大小，线程池会保持这些核心线程，直到线程池关闭
    private volatile int corePoolSize;
    // 线程池允许的最大线程数，超过这个数量的线程无法再被创建
    private volatile int maximumPoolSize;

    // 一个阻塞队列，用于存储等待执行的任务
    private final BlockingQueue<Runnable> workQueue;

    public T01_ThreadPoolTrader(int corePoolSize, int maximumPoolSize, BlockingQueue<Runnable> workQueue) {
        this.corePoolSize = corePoolSize;
        this.maximumPoolSize = maximumPoolSize;
        this.workQueue = workQueue;
    }


    @Override
    public void execute(Runnable command) {
        int c = cti.get();
        if(c < corePoolSize) {
            if(!addWorker(command)) {
                reject();
            }
        }
        if(!workQueue.offer(command)) {
            if(!addWorker(command)) {
                reject();
            }
        }
    }

    private boolean addWorker(Runnable firstTask) {
        if(cti.get() >= maximumPoolSize) return false;

        Worker worker = new Worker(firstTask);
        worker.thread.start();
        cti.incrementAndGet();
        return true;
    }

    private final class Worker implements Runnable {
        final Thread thread;
        Runnable firstTask;

        public Worker(Runnable firstTask) {
            this.thread = new Thread(this);
            this.firstTask = firstTask;
        }

        @Override
        public void run() {
            Runnable task = firstTask;
            try{
                while(task != null || (task = getTask()) != null) {
                    task.run();
                    if (cti.get() > maximumPoolSize) {
                        break;
                    }
                    task = null;
                }
            }finally {
                cti.decrementAndGet();
            }
        }

        private Runnable getTask() {
            for(;;) {
                System.out.println("workQueue.size: " + workQueue.size());
                try {
                    return workQueue.take();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void reject() {
        throw new RuntimeException("Error！ctl.count：" + cti.get() + " workQueue.size：" + workQueue.size());
    }

    public static void main(String[] args) {
        T01_ThreadPoolTrader threadPoolTrader = new T01_ThreadPoolTrader(2, 2, new LinkedBlockingQueue<Runnable>(10));
        for (int i = 0; i < 20; i++) {
            int finalI = i;
            threadPoolTrader.execute(() -> {
                try {
                    Thread.sleep(1500);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                System.out.println("任务编号：" + finalI);
            });
        }
    }
}
