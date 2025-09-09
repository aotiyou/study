package cn.com.zxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LocationAwareLogger;

/**
 * @author infosec
 * @since 2025/3/3
 */
public class SLF4JImpl implements Log {

    private static final String callerFQCN = SLF4JImpl.class.getName();
    private static final Logger testLogger = LoggerFactory.getLogger(SLF4JImpl.class);

    static {
        if (!(testLogger instanceof LocationAwareLogger)) {
            throw new UnsupportedOperationException(testLogger.getClass() + " is not a suitable logger");
        }
    }

    private LocationAwareLogger log;

    public SLF4JImpl(LocationAwareLogger log) {
        this.log = log;
    }

    public SLF4JImpl(String loggerName) {
        this.log = (LocationAwareLogger) LoggerFactory.getLogger(loggerName);
    }


    @Override
    public boolean isDebugEnabled() {
        return log.isDebugEnabled();
    }

    @Override
    public void debug(String msg) {
        log.log(null, callerFQCN, LocationAwareLogger.DEBUG_INT, msg, null, null);
    }

    @Override
    public void debug(String msg, Throwable t) {
        log.log(null, callerFQCN, LocationAwareLogger.DEBUG_INT, msg, null, t);
    }

    @Override
    public boolean isErrorEnabled() {
        return log.isErrorEnabled();
    }

    @Override
    public void error(String msg) {
        log.log(null, callerFQCN, LocationAwareLogger.ERROR_INT, msg, null, null);
    }

    @Override
    public void error(String msg, Throwable t) {
        log.log(null, callerFQCN, LocationAwareLogger.ERROR_INT, msg, null, t);
    }

    @Override
    public boolean isInfoEnabled() {
        return log.isInfoEnabled();
    }

    @Override
    public void info(String msg) {
        log.log(null, callerFQCN, LocationAwareLogger.INFO_INT, msg, null, null);
    }

    @Override
    public void info(String msg, Throwable t) {
        log.log(null, callerFQCN, LocationAwareLogger.INFO_INT, msg, null, t);
    }

    @Override
    public boolean isWarnEnabled() {
        return log.isWarnEnabled();
    }

    @Override
    public void warn(String msg) {
        log.log(null, callerFQCN, LocationAwareLogger.WARN_INT, msg, null, null);
    }

    @Override
    public void warn(String msg, Throwable t) {
        log.log(null, callerFQCN, LocationAwareLogger.WARN_INT, msg, null, t);
    }

    @Override
    public boolean isTraceEnabled() {
        return log.isTraceEnabled();
    }

    @Override
    public void trace(String msg) {
        log.log(null, callerFQCN, LocationAwareLogger.TRACE_INT, msg, null, null);
    }

    @Override
    public void trace(String msg, Throwable t) {
        log.log(null, callerFQCN, LocationAwareLogger.TRACE_INT, msg, null, t);
    }
}
