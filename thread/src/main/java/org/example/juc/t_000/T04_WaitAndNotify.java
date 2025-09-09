package org.example.juc.t_000;

import org.checkerframework.checker.units.qual.C;

/**
 * @author infosec
 * @since 2024/12/18
 */
public class T04_WaitAndNotify {

    public static void main(String[] args) {
        Boss boss = new Boss();
        Waiter waiter = new Waiter(boss);
        Guest guest = new Guest(boss);

        new Thread(waiter).start();
        new Thread(guest).start();

        System.out.println(1111111);

    }


    static class Waiter implements Runnable {

        Boss boos;

        public Waiter(Boss boos) {
            this.boos = boos;
        }

        @Override
        public void run() {
            int i = 1;
            while (true) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                if(i == 1) {
                    try {
                        boos.onlineWaiter("美式咖啡", "500 美元");
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    try {
                        boos.onlineWaiter("土耳其咖啡", "100 美元");
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                i = (i + 1) % 2;
            }
        }
    }

    static class Guest implements Runnable {

        Boss boss;

        public Guest(Boss boss) {
            this.boss = boss;
        }

        @Override
        public void run() {
            while (true) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                try {
                    boss.haveCoffee();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    static class Boss {

        private String waiter = null;
        private String price = null;
        private boolean isBusy = true;

        public synchronized void onlineWaiter(String waiter, String price) throws InterruptedException {
            if(!isBusy) {
                wait();
            }
            this.waiter = waiter;
            this.price = price;
            isBusy = false;
            notify();
        }

        public synchronized void haveCoffee() throws InterruptedException {
            if(isBusy) {
                wait(); // 等待
            }

            System.out.println("做咖啡：" + waiter);
            System.out.println("价格: " + price);
            System.out.println("  " + "  " + "  " + "  " + "  " + "  " + "  " + "  " + "  " + "  " + waiter + "完事" + "准备 ... ...");
            System.out.println("****************************************");
            isBusy = true;
            notify(); // 叫醒
        }
    }

}
