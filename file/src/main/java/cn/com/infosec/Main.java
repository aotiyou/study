package cn.com.infosec;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) {
        File file = new File("C:\\Users\\user\\Desktop\\密码机\\test.txt");
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line1 = null;
            String line2 = null;
            String srcHash = null;
            boolean checked = true;

            while ((line1 = reader.readLine()) != null && (line2 = reader.readLine()) != null) {
                System.out.println("line1 = " + line1);
                System.out.println("line2 = " + line2);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void test() throws IOException {
        Path tempFile = Files.createTempFile("log-catch-", ".tmp");
        System.out.println("tempFile = " + tempFile);
    }

}
