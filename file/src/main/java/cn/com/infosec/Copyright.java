package cn.com.infosec;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

/**
 * @author infosec
 * @since 2025/9/23
 */
public class Copyright {

    public static void main(String[] args) throws IOException {
        String outputDir = "D:\\infosec\\项目-华为红线\\copyright";
        String inputFile = "D:\\infosec\\项目-华为红线\\copyright\\copyright.txt";

        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile))) {
            String line;
            int count = 1;
            while ((line = reader.readLine()) != null) {
                String outputFile = outputDir + "/" + line + ".txt";
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
                    writer.write(line);
                }
                count++;
            }
        }

    }

}
