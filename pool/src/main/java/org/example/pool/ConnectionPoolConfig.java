package org.example.pool;

import org.apache.commons.pool2.impl.GenericObjectPoolConfig;

/**
 * @author aotiyou
 * @since 2025/9/9
 */
public class ConnectionPoolConfig extends GenericObjectPoolConfig {

    public ConnectionPoolConfig() {
        setMinIdle(10);//最小空闲对象数
        setMaxIdle(100);//最大空闲对象数
        setMaxWaitMillis(30000);//允许最大等待时间毫秒数
        setMaxTotal(1500);//最大活动对象数
        setTestWhileIdle(true);//对池中空闲连接进行检验
        setSoftMinEvictableIdleTimeMillis(1000 * 60 * 5);//对象最小空闲时间，超过此时间移除对象
        setTimeBetweenEvictionRunsMillis(1000 * 60 * 10);//检测空闲对象周期
    }
}
