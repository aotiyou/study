package org.example;

import org.junit.Test;

import java.math.BigDecimal;

/**
 * @author infosec
 * @since 2025/3/18
 */
public class BigDecimalTest {

    @Test
    public void test() {
        String str = "9.5555";
        BigDecimal bd = new BigDecimal(str);
        BigDecimal subtract = bd.subtract(BigDecimal.valueOf(0.01));
        System.out.println(subtract);

        if(new BigDecimal("32").compareTo(bd) == 1) {
            System.out.println("32大于"+bd);
        }else {
            System.out.println("32小于"+bd);
        }

    }

}
