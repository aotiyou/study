package org.example.juc.t_000;

/**
 * @author infosec
 * @since 2024/9/11
 */
public class Test {

    private static int i = 0;

    public static void main(String[] args) {
        for(int i=0; i<100; i++) {
            new Thread(() -> {
                test();

                System.out.println(Thread.currentThread().getName());
            }).start();
        }
    }

    public static synchronized void test() {
        System.out.println(++i);
    }

}
