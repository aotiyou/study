package org.example;

import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OutOfMemoryErrorTest {

    @Test
    public void javaHeapSpaceError() {
        List<String> list = new ArrayList<String>();
        while (true) {
            list.add("1");
        }
    }


    @Test
    public void gcOverheadLimitExceededError() {
        List<Map<String, Object>> mapList = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            Map<String, Object> map = new HashMap<>();
            for (int j = 0; j < i; j++) {
                map.put(String.valueOf(j), j);
            }
            mapList.add(map);
        }
    }


}
