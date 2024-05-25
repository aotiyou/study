package cn.com.infosec;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        StringBuilder sb = new StringBuilder();
        sb.append("127.0.0.1:514,127.0.0.2:514,127.0.0.3:514,127.0.0.4:514,127.0.0.5:514,127.0.0.6:514");

        String srcStr = "127.0.0.1:514,127.0.0.2:514,127.0.0.3:514,127.0.0.4:514,127.0.0.5:514,127.0.0.6:514";

        String str = "127.0.0.2:514";
        String str2 = "1.1.1.1:514666";
        int strIndex = sb.toString().indexOf(str);
        sb.replace(strIndex, strIndex + str.length(), str2);
        System.out.println(sb.toString());
    }

    @Test
    public void test() {
        String sysMult = "1.11.111.1111:111:level,2.22.222.2222:222:info,3.33.333.3333:333:warn";

        String[] sysConfigArr = sysMult.split(",");
        String[] ipConfigArr = new String[sysConfigArr.length];
        String[] levelConfigArr = new String[sysConfigArr.length];
        for (int i = 0; i < sysConfigArr.length; i++) {
            ipConfigArr[i] = sysConfigArr[i].substring(0, sysConfigArr[i].lastIndexOf(":"));
            levelConfigArr[i] = sysConfigArr[i].substring(sysConfigArr[i].lastIndexOf(":") + 1);
        }
        for (String ipConfig : ipConfigArr) {
            System.out.println(ipConfig);
        }

        for (String levelConfig : levelConfigArr) {
            System.out.println(levelConfig);
        }
    }

    @Test
    public void test2() {
        String ipAddress = "SYSLOG_10.80.61.122:514";
        String[] ipInfo = ipAddress.split("[_:]");
        System.out.println(ipInfo[1] + ipInfo[2]);
    }

    @Test
    public void test3() {
        String syslogMultiple = "1.11.111.1111:111:level,2.22.222.2222:222:info,3.33.333.3333:333:warn";
        String syslogType = "1,2,3,4,5";

        List<String> syslogIpDel = new ArrayList<>();
        syslogIpDel.add("SYSLOG_1.11.111.1111:111:info");
        syslogIpDel.add("SYSLOG_2.22.222.2222:222:info");
        syslogIpDel.add("SYSLOG_3.33.333.3333:333:warn");
        syslogIpDel.add("SYSLOG_10.80.61.122:514:error");


        List<String> syslogIpAdd = new ArrayList<>();
        List<String> syslogIpNew = new ArrayList<>();
        String[] sysConfigArr = syslogMultiple.split(",");
//                    String[] ipsArray = new String[sysConfigArr.length];
//                    String[] levelArray = new String[sysConfigArr.length];
//                    for (int i = 0; i < sysConfigArr.length; i++) {
//                        ipsArray[i] = sysConfigArr[i].substring(0, sysConfigArr[i].lastIndexOf(":"));
//                        levelArray[i] = sysConfigArr[i].substring(sysConfigArr[i].lastIndexOf(":") + 1);
//                    }
        List<String> logTypeArray = Arrays.asList(syslogType.split(","));
        //构造新的转发地址
        for (String ip : sysConfigArr) {
            syslogIpAdd.add("SYSLOG_" + ip);
            syslogIpNew.add("SYSLOG_" + ip);
        }

        //去重
        syslogIpAdd.removeAll(syslogIpDel);
        syslogIpDel.removeAll(syslogIpNew);

        for (String syslogIp : syslogIpDel) {
            System.out.println("del syslogIp = " + syslogIp);
        }

        for (String syslogIp : syslogIpNew) {
            System.out.println("new syslogIp = " + syslogIp);
        }

        for (String syslogIp : syslogIpAdd) {
            System.out.println("add syslogIp = " + syslogIp);
        }

    }

}
