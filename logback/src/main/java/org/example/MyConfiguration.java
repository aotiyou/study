package org.example;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.filter.ThresholdFilter;
import ch.qos.logback.classic.net.SyslogAppender;
import ch.qos.logback.classic.spi.Configurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy;
import ch.qos.logback.core.spi.ContextAwareBase;
import ch.qos.logback.core.util.FileSize;
import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;

/**
 * @author infosec
 * @since 2024/3/19
 */
public class MyConfiguration extends ContextAwareBase implements Configurator {


    @Override
    public void configure(LoggerContext loggerContext) {
//        RollingFileAppender<ILoggingEvent> test = getFileAppender("test", loggerContext);
        ch.qos.logback.classic.Logger logger = loggerContext.getLogger(Logger.ROOT_LOGGER_NAME);
//        logger.addAppender(test);

        SyslogAppender syslogAppender = getSyslogAppender("127.0.0.1", 514, loggerContext, "info");
        logger.addAppender(syslogAppender);
    }

    public static RollingFileAppender<ILoggingEvent> getFileAppender(String appenderName, LoggerContext context) {
        String file = "/opt/test_run.log";

        RollingFileAppender<ILoggingEvent> fileAppender = new RollingFileAppender();
        fileAppender.setName(appenderName);
        fileAppender.setAppend(true);
        fileAppender.setFile(file);

        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setPattern("%msg%n");
        encoder.setCharset(StandardCharsets.UTF_8);
        encoder.setContext(context);
        encoder.start();
        fileAppender.setEncoder(encoder);

        String logFilePattern = "/opt/MY_PLACEHOLDER_run_%i.log";
        logFilePattern = logFilePattern.replace("MY_PLACEHOLDER", appenderName);
        FileSize maxFileSize = FileSize.valueOf("1MB");
        int minIndex = Integer.parseInt("0");
        int maxIndex = Integer.parseInt("3");

        FixedWindowRollingPolicy rollingPolicy = new FixedWindowRollingPolicy();
        rollingPolicy.setContext(context);
        rollingPolicy.setParent(fileAppender);
        rollingPolicy.setFileNamePattern(logFilePattern);
        rollingPolicy.setMinIndex(minIndex);
        rollingPolicy.setMaxIndex(maxIndex);
        rollingPolicy.start();
        fileAppender.setRollingPolicy(rollingPolicy);

        SizeBasedTriggeringPolicy triggeringPolicy = new SizeBasedTriggeringPolicy();
        triggeringPolicy.setContext(context);
        triggeringPolicy.setMaxFileSize(maxFileSize);
        triggeringPolicy.start();
        fileAppender.setTriggeringPolicy(triggeringPolicy);

        fileAppender.setContext(context);
        fileAppender.start();
        return fileAppender;
    }


    public static SyslogAppender getSyslogAppender(String ip, Integer port, LoggerContext context, String level) {
        SyslogAppender appender = new SyslogAppender();
        appender.setName("SYSLOG_" + ip + ":" + port + ":" + level);
        appender.setSyslogHost(ip);
        appender.setPort(port);
        appender.setFacility("LOCAL0");
        appender.setSuffixPattern("%msg");
        appender.setContext(context);
        ThresholdFilter filter = new ThresholdFilter();
        filter.setLevel(level);
        filter.start();
        appender.addFilter(filter);
        appender.start();
        return appender;
    }
}
