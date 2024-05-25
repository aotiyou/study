package org.example;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy;
import ch.qos.logback.core.util.FileSize;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {

        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

//        while(true){
            LOG.trace("A Message From LOGGER：{}", "Hello TRACE");
            LOG.debug("A Message From LOGGER：{}", "Hello DEBUG");
            LOG.info("A Message From LOGGER：{}", "Hello INFO");
            LOG.warn("A Message From LOGGER：{}", "Hello WARN");
            LOG.error("A Message From LOGGER：{}", "Hello ERROR");
//        }

    }

//    public static ch.qos.logback.classic.Logger logger() {
//        LoggerContext context = (LoggerContext)LoggerFactory.getILoggerFactory();
//        Logger logLogger = context.getLogger(Main.class);
//        RollingFileAppender<ILoggingEvent> rollingFileAppender = getFileAppender("test", context);
//        logLogger.addAppender(rollingFileAppender);
//    }



}
