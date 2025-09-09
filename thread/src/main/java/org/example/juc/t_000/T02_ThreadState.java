package org.example.juc.t_000;

import com.google.common.annotations.VisibleForTesting;
import org.junit.Test;

/**
 * Thread 状态测试
 * @author infosec
 * @since 2024/12/18
 */
public class T02_ThreadState {

    /**
     * 线程状态: NEW
     */
    @Test
    public void testNewState() {

        Thread thread = new Thread(new Runnable() {

            @Override
            public void run() {

            }
        });
        System.out.println("线程状态: " + thread.getState());
    }

    /**
     * 线程状态: RUNNABLE
     */
    @Test
    public void testRunnableState() {
        Thread thread = new Thread(() -> {
        });

        thread.start();

        System.out.println("线程状态: " + thread.getState());
    }

    /**
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: BLOCKED
     * 线程状态: WAITING
     * 线程状态: WAITING
     * 线程状态: WAITING
     * 线程状态: WAITING
     *
     * 为了让两个线程发生锁竞争
     * 第一个线程，synchronized获取锁后休眠，不释放锁
     * 第二个线程，synchronized获取不到锁，会被挂起
     * 那么最后的输出结果就是： BLOCKED
     */
    @Test
    public void testBlockedState() {
        Object obj = new Object();
        new Thread(() -> {
            synchronized (obj) {
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }).start();

        Thread thread = new Thread(() -> {
            synchronized (obj) {
                try {
                    obj.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();
        while (true) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("线程状态: " + thread.getState());
        }
    }

    /**
     * 线程状态: WAITING
     * 只要在synchronized代码块或者修饰的方法中，调用wait方法，又没有被notify就会进入WAITING状态
     * 另外 Thread.join 源码中也是调用的wait方法，所以也会让线程进入等待状态
     */
    @Test
    public void testWaitingState() throws InterruptedException {
        Object obj = new Object();
        Thread thread = new Thread(() -> {
            synchronized (obj) {
                try {
                    obj.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        thread.start();
        thread.join();

        while (true) {
            Thread.sleep(1000);
            System.out.println("线程状态: " + thread.getState());
        }
    }

    @Test
    public void testWaitingState2() throws InterruptedException {
        Thread thread_a = new Thread(() -> {
            try {
                Thread.sleep(3000); // 模拟线程A执行，睡眠3秒
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("线程A已完成");
        });

        // 启动线程A
        thread_a.start();

        // 打印主线程状态，主线程将在这里等待线程A
        while (thread_a.isAlive()) {
            System.out.println("主线程状态: " + Thread.currentThread().getState());  // 主线程状态通常是RUNNABLE
            System.out.println("线程A状态: " + thread_a.getState());  // 线程A会处于TIMED_WAITING状态
            Thread.sleep(1000);  // 每隔1秒打印一次
        }

        // 线程A结束后，主线程继续执行
        System.out.println("线程A状态: " + thread_a.getState());  // 线程A会处于TERMINATED状态
        System.out.println("主线程状态: " + Thread.currentThread().getState());  // 主线程会处于RUNNABLE状态
    }

    /**
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TIMED_WAITING
     * 线程状态: TERMINATED
     */
    @Test
    public void testTimeWaitingState() throws InterruptedException {
        Object obj = new Object();
        Thread thread = new Thread(() -> {
            synchronized (obj) {
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();
        while (thread.isAlive()) {
            Thread.sleep(1000);
            System.out.println("线程状态: " + thread.getState());
        }
    }


}
