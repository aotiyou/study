package org.example.juc.t_000;

/**
 * @author infosec
 * @since 2024/12/18
 */
public class T05_Join {

    public static void main(String[] args) throws InterruptedException {

        Thread thread = new Thread(() -> {
            System.out.println("thread before");
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("thread after");
        });

        thread.start();
        System.out.println("main begin!");
        thread.join();
        System.out.println("main end!");


    }

}
