//package cn.com.zxy;
//
//import java.lang.reflect.Constructor;
//
///**
// * @author infosec
// * @since 2025/3/3
// */
//public class LogFactory {
//
//    private static Constructor logConstructor;
//
//    static {
//        String logType= System.getProperty("logType");
//        if(logType != null){
//            if(logType.equalsIgnoreCase("slf4j")){
//                tryImplementation("org.slf4j.Logger", "logging.slf4j.SLF4JImpl");
//            }
//        }
//        // 优先选择log4j,而非Apache Common Logging. 因为后者无法设置真实Log调用者的信息
//        tryImplementation("org.slf4j.Logger", "logging.slf4j.SLF4JImpl");
//        if (logConstructor == null) {
//            try {
//                logConstructor = NoLoggingIsmpl.class.getConstructor(String.class);
//            } catch (Exception e) {
//                throw new IllegalStateException(e.getMessage(), e);
//            }
//        }
//    }
//
//    private static void tryImplementation(String testClassName, String implClassName) {
//        if (logConstructor != null) {
//            return;
//        }
//
//        try {
//            Resources.classForName(testClassName);
//            Class implClass = Resources.classForName(implClassName);
//            logConstructor = implClass.getConstructor(new Class[] { String.class });
//
//            Class<?> declareClass = logConstructor.getDeclaringClass();
//            if (!Log.class.isAssignableFrom(declareClass)) {
//                logConstructor = null;
//            }
//
//            try {
//                if (null != logConstructor) {
//                    logConstructor.newInstance(LogFactory.class.getName());
//                }
//            } catch (Throwable t) {
//                logConstructor = null;
//                //t.printStackTrace();
//            }
//
//        } catch (Throwable t) {
//            //t.printStackTrace();
//        }
//    }
//
//    public static Log getLog(Class clazz) {
//        return getLog(clazz.getName());
//    }
//
//    public static Log getLog(String loggerName) {
//        try {
//            System.out.println(logConstructor);
//            return (Log) logConstructor.newInstance(loggerName);
//        } catch (Throwable t) {
//            throw new RuntimeException("Error creating logger for logger '" + loggerName + "'.  Cause: " + t, t);
//        }
//    }
//
//}
