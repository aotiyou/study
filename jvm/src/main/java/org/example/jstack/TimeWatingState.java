package org.example.jstack;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author infosec
 * @since 2024/3/13
 */
public class TimeWatingState {

    // java的显示锁，类似java对象内置的监视器
    private static Lock lock = new ReentrantLock();

    // 锁关联的条件队列（类似于object.wait）
    private static Condition condition = lock.newCondition();

    public static void main(String[] args) {
        Runnable task = new Runnable() {
            @Override
            public void run() {
                // 加锁，进入临界区
                lock.lock();

                try {
                    System.out.println(Thread.currentThread().getName() + " 进入临界区");

                    // 休眠10秒
                    condition.await(5, TimeUnit.MINUTES);

//                    Thread.sleep(5 * 60 * 1000);

                    System.out.println(Thread.currentThread().getName() + " 退出临界区");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } finally {
                    // 释放锁
                    lock.unlock();
                }
            }
        };

        new Thread(task, "t1").start();
        new Thread(task, "t2").start();
    }


}
