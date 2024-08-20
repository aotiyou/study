package com.example.design;

import cn.com.infosec.netsign.base.processors.util.ShellUtil;
import cn.com.infosec.netsign.base.util.NetSignImpl;
import cn.com.infosec.netsign.basic.system.ServerConfig;
import cn.com.infosec.netsign.basic.system.SystemInfoConsts;
import cn.com.infosec.netsign.config.BasicConfigManager;
import cn.com.infosec.netsign.config.BasicExtensionConfig;
import cn.com.infosec.netsign.config.BasicLogConfig;
import cn.com.infosec.netsign.config.SerialVersionConfig;
import cn.com.infosec.netsign.crypto.util.Base64;
import cn.com.infosec.netsign.crypto.util.CryptoUtil;
import cn.com.infosec.netsign.frame.util.ConfigUtil;
import cn.com.infosec.netsign.logger.ConsoleLogger;
import cn.com.infosec.netsign.proxy.operation.utils.FileUtil;

import java.io.*;
import java.util.Properties;

public class ExtendedConfigOld {

    private static SerialVersionConfig versionConfig;


    /**
     * 云服务主类
     */
    private static String hgfPath = null;
    private static Properties prop = null;


    private static int threadPoolCore = 70;

    private static int threadPoolMax = 500;

    private static int threadPoolQueue = 30000;

    // 是否在线程池执行任务时是否缓存线程，如果不进行缓存在长连接时修改配置后需要等超时
    private static boolean isCatchHandler = false;

    // 单位为k
    private static int logBuffer = 80;

    private static String syslogSystem = "local0";

    private static String syslogAccess = "local1";

    private static String syslogDebug = "local2";

    private static boolean isPrintST = true;

    private static boolean isDebug = true;

    private static boolean isSave = true;

    private static String nohupLogConfig = null;

    private static boolean isCheckCertValidity = true;

    private static String encoding = null;

    // jmx监控等级
    private static String jmxMonitorLevel = "none";

    // jmx监控等级：不监控
    public static final String JMX_MONITOR_LEVEL_NONE = "none";

    // jmx监控等级：只监控系统信息
    public static final String JMX_MONITOR_LEVEL_SYSTEM = "system";

    // jmx监控等级：监控所有信息
    public static final String JMX_MONITOR_LEVEL_FULL = "full";

    // 最大监控项目队列
    private static int taskQueueMax = 2000;

    // 查询监控项目队列的时间间隔
    private static long taskQueueWatchInterval = 60000;
    // TODO 2020/02/19 查询统计间隔时间
    private static long queryTime = 100000;
    //后台处理为微秒
    private static long intervalMaximum;
    private static long intervalMinimum;
    //
    private static long serviceInfoCollectInterval = 60000;

    private static int maxReadThread = 10;

    public static final String SHELL_FILE_NAME_CPUSTATUS = "cpustat";

    public static final String SHELL_FILE_NAME_MAXMEMORY = "maxmem";

    public static final String SHELL_FILE_NAME_FREEMEMORY = "freemem";

    public static final String SHELL_FILE_NAME_MAXHARDDISK = "maxhd";

    public static final String SHELL_FILE_NAME_FREEHARDDISK = "freehd";

    public static final String SHELL_FILE_NAME_TCPTRANSSTAT = "tcptrans";

    public static final String SHELL_FILE_NAME_TCPCONNCOUNT = "tcpcc";

    // 5.5.40.14
    private static boolean USE_TCP_CONNCOUNT = false;

    private static int projectID = 0;

    // 使用p11还是jce
    // 是否使用硬件做签名运算。配hard适用于卫士通卡。5.5.30后不支持
    @Deprecated
    private static String algMode = "soft";

    /**
     * 验签provider
     */
    private static String verifyProvider = "INFOSEC";
    private static String[] verifyProviders = null;
    /**
     * 签名provide
     */
    private static String signProvider = "INFOSEC";
    private static String[] signProviders = null;

    /**
     * 公钥加密
     */
    private static String encryptProvider = "INFOSEC";

    /**
     * 私钥解密
     */
    private static String decryptProvider = "INFOSEC";

    /**
     * 对称加解密
     */
    private static String symmProvider = "INFOSEC";


    private static int backLog = 200;

    public static final int PDF_ALLOW_ASSEMBLY = 1024;

    public static final int PDF_ALLOW_COPY = 16;

    public static final int PDF_ALLOW_DEGRADED_PRINTING = 4;

    public static final int PDF_ALLOW_FILL_IN = 256;

    public static final int PDF_ALLOW_MODIFY_ANNOTATIONS = 32;

    public static final int PDF_ALLOW_MODIFY_CONTENTS = 8;

    public static final int PDF_ALLOW_PRINTING = 2052;

    public static final int PDF_ALLOW_SCREENREADERS = 512;

    // ---2013-12-05(create) LH.
    public static String subFilter = "adbe.pkcs7.detached";

    // 根据需要指定默认的签名注释文字和签章文件
    public static String signNotation = "";

    public static String stampFile = "";

    private static int[] pdfPermissions = new int[]{-1};

    private static boolean inBlackList;

    private static int[] crlCleanTimes;

    private static long reloadCRLInterval;

    private static String crlLoadMode;

    private static boolean supportsm2 = false;

    private static boolean sm2UseHardKeyStore = false;

    private static boolean useHardKeyStore = false;

    private static boolean sm2SignUseHardALG = true;

    private static boolean sm2VerifyUseHardALG = true;

    private static String sm2Provider = null;

    private static String defaultSM2P10Alg = "SM3withSM2";

    private static byte[] SM3CertpucID = null;

    private static byte[] SM3P10PucID = null;

    private static byte[] SM3SignpucID = null;

    private static byte[] SM3OCSPPucID = null;

    private static String SM3CertpucIDString = null;

    private static String SM3P10PucIDString = null;

    private static String SM3SignpucIDString = null;

    private static String SM3OCSPPucIDString = null;


    private static boolean sm2Cache = false;

    private static int sm2CacheSize = 0;

    private static String sm2SignGear = "0/1";

    private static String sm2VerifyGear = "0/1";

    // 生成P7包时是否包含证书链
    private static boolean withCertChain = false;

    // 是否自动重新加载资源
    private static boolean isAutoReloadResources = false;

    private static long resourceReloadInterval = 1000 * 60 * 60;

    private static boolean isAutoUnzip = false;

    private static String privateKeyAlg = null;

    private static boolean isReturnVerifyResult = true;

    private static boolean isReturnSignResult = true;

    // soeck session monitor配置，用于主动关闭闲置的socket连接
    private static boolean isSessionMonitorOpen = false;

    private static int maxSessionPoolSize = 10240;

    private static boolean p7VerifySupportAuthAttrs = true;
    private static boolean p7verifyWithLength = false;

    private static boolean rsaSignUsingQ7 = false;

    private static boolean sm2SignUsingQ7 = true;

    private static boolean rsaEncUsingQ7 = false;

    private static boolean ecEncUsingQ7 = false;

    private static boolean ecSigUsingQ7 = true;

    private static boolean sm2EncUsingQ7 = true;

    private static boolean envelopSM4OIDUseUnStandard = false;

    private static boolean isUsingCImp = false;
    private static boolean isUsingCSM3 = false;

    private static boolean envelopCache;

    private static int envelopCacheSize;

    private static String encryptGear;

    private static String decryptGear;

    private static boolean integerUnsigned = true;

    /**
     * @author Hoary.Huang
     * @return 产生P10 时候的空节点是否保留。true保留，false不保留
     * 适用于RSA
     * @since 5.5.40.16 2020.12.30
     */
    private static boolean p10RsaWithNull = true;

    /**
     * @author Hoary.Huang
     * @return 产生P10 时候的空节点是否保留。true保留，false不保留
     * 适用于 SM2
     * @since 5.5.40.16 2020.12.30
     */
    private static boolean p10Sm2WithNull = true;


    private static boolean p10CFCAWithAttibute = false;
    private static boolean p7WithNull = false;

    private static boolean isLogRespTime = true;

    private static long longBusinessTime = 500;

    private static boolean isCheckBankID = true;

    private static boolean KLBSignOuterFields = true;

    private static String hardKeyStoreDevice = null;

    private static String hardKeyStroreBackupPassword = null;

    /**
     * below
     *
     * @since 5.5.40.12
     */
    private static boolean checkWeekAlg = false;

    private static boolean isCacheCert = true;

    private static boolean isVerifyCertChain = true;

    private static boolean isSupportIssuerKid = true;

    private static boolean isIssuerDNCaseMatch = true;

    /**
     * below
     *
     * @since 5.5.40.12 patch6
     */
    private static short signProviderWheel = 0;

    private static short verifyProviderWheel = 0;

    private static Object signProviderLock = new Object();

    private static Object verifyProviderLock = new Object();

    private static boolean needCheckOSCCAStandards = false;

    private static boolean ECSigMustQ7 = false;
    private static boolean ECSignUseECAlgWithP7=false;
    private static boolean SM2SigMustQ7 = false;

    private static boolean RSASigMustQ7 = false;

    private static boolean SM2SigMustSeq = false;

    private static boolean SM2SigMustUnsignedInt = false;

    private static boolean SM2SigMustSignedInt = false;

    //网联平台是否每次加密都产生随机密钥
    private static boolean wanglianGenRandomKey = false;

    /**
     * 自动GC时间间隔，测试参数，0为不进行GC
     *
     * @since bjcp1.2
     */
    private static int autoGCInterval = 0;

    /**
     * 强制进行gc
     */
    private static boolean forceGC = false;

    /**
     * 强制GC的另一个触发条件，老生代占比
     */
    private static int oldGenUsedRatio = 0;

    private static int genKeyPairGear = 1;

    /**
     * @since 5.5.40.12 patch15
     */
    private static boolean isDeleteRAWCert = true;

    /**
     * 是否发送notice
     *
     * @since 5.5.40.12 patch16
     */
    private static boolean isSendNotice = false;

    /**
     * 验国密签名前是否检查公钥合法性
     *
     * @since 5.5.40.12 patch16
     */
    private static boolean isCheckSM2Pubk = true;


    /**
     * 上传证书时，以该字符开头的bankid，不做检查
     *
     * @since 5.5.40.12 patch17
     */
    private static String[] nocheckBankid = new String[0];

    private static boolean envelopeSignerIDUseKid = true;

    /**
     * 非对称密钥延迟加载
     *
     * @since 5.5.40.12 patch31 黑龙江CA
     */
    private static boolean lazyLoadAsymmKey = true;
    /**
     * 证书文件是否单独存储
     *
     * @since 5.5.40.12 patch31 黑龙江CA
     */
    private static boolean extractCertFile = true;
    /**
     * keypair列表索引是否使用CN DN,默认开启，开启后可能会造成索引冲突，风险自担
     *
     * @since 5.5.40.12 patch31 黑龙江CA
     */
    private static boolean useCnAndDnIndex = true;

    /**
     * 使用密钥池
     * sm2密钥池的容量
     *
     * @since 5.5.40.12 patch32.1 浦发银行 2019-12-12
     */
    private static int sm2PoolSize = 0;

    /**
     * RSA1024密钥池的容量
     */
    private static int rsa1024PoolSize = 0;

    /**
     * RSA2048密钥池的容量
     */
    private static int rsa2048PoolSize = 0;

    /**
     * 线程池自定义线程数
     */
    private static int threadCount4KeyPairPool = 0;
    /**
     * 开启加密卡同步锁
     */
    private static boolean lock4CryptoCard = true;

    /**
     * 财政部：解数字信封验证书
     */
    private static boolean decryptEnvelopeCheckCert = false;


    /**
     * 同步支持批量同步，此时需要关闭启动时同步
     */
    private static boolean synBatch = true;

    /**
     * 同步关联服务器定时检测默认超时时间,超过此时间认为关联服务器任务不可用。退出本次任务
     * 加这个参数是因为防止设置超时时间过大，导致长时间不返回导致队列无限增大
     * 设置超过15秒就任务设备为下线状态
     */
    private static long synScheduledServiceTimeOut = 15000;

    private static boolean regenerateCryptoTextForSM2;

    /**
     * 是否记录进入processor的时间
     */
    private static boolean isRecordingStartTime = false;

    public static boolean isRegenerateCryptoTextForSM2() {
        return regenerateCryptoTextForSM2;
    }

    public static void setRegenerateCryptoTextForSM2(boolean regenerateCryptoTextForSM2) {
        ExtendedConfigOld.regenerateCryptoTextForSM2 = regenerateCryptoTextForSM2;
    }

    public static boolean isDecryptEnvelopeCheckCert() {
        return decryptEnvelopeCheckCert;
    }

    public static long getSynScheduledServiceTimeOut() {
        return synScheduledServiceTimeOut;
    }

    public static void setSynScheduledServiceTimeOut(long synScheduledServiceTimeOut) {
        ExtendedConfigOld.synScheduledServiceTimeOut = synScheduledServiceTimeOut;
    }

    public static boolean isIsRecordingStartTime() {
        return isRecordingStartTime;
    }

    public static void setIsRecordingStartTime(boolean isRecordingStartTime) {
        ExtendedConfigOld.isRecordingStartTime = isRecordingStartTime;
    }

    //todo-----------
    /**
     * 加密证书验签
     */
    private static boolean encCertForSign = false;

    public static boolean isEncCertForSign() {
        return encCertForSign;
    }

    private static boolean snWith0;
    /**
     * todo
     * 是否收集交易数据写在数据库里
     *
     * @since tips
     */
    private static boolean isCollectData = false;

    /**
     * 密钥池配置
     *
     * @since 5.5.40 WCS1.2
     * @since 合并微信开户项目 20191028
     */
    private static int genRSA1024PoolSize = 0;
    private static int genRSA1024ThreadCount = 0;
    private static int genRSA2048PoolSize = 0;
    private static int genRSA2048ThreadCount = 0;
    private static String wechartstockEncpassword = "123456";

    /**
     * 加密机版本新增 导入/生成对称密钥是否检查密钥、算法的正确性、导入非对称密钥是否检查密钥对
     */
    private static boolean isCheckMatch = true;

    private static boolean sdfMode = false;


    /**
     * @since 交行-9152需求
     * 说明: 只获取一次，所以可以不用set
     */
    private static String queryLoader;

    private static boolean subjectQuery;

    private static boolean checkOSCCAStandards4PBC2G = false;

    private static boolean checkSM2OSCCAStandards4PBC2G = true;

    private static boolean isExtKeyUseCard = true;
    private static boolean caviumUseSoftWhenFailed;

    public static boolean isCaviumUseSoftWhenFailed() {
        return caviumUseSoftWhenFailed;
    }

    public static void setCaviumUseSoftWhenFailed(boolean caviumUseSoftWhenFailed) {
        ExtendedConfigOld.caviumUseSoftWhenFailed = caviumUseSoftWhenFailed;
    }

    public static boolean ExtKeyUseCard() {
        return isExtKeyUseCard;
    }

    public static void setIsExtKeyUseCard(boolean isExtKeyUseCard) {
        ExtendedConfigOld.isExtKeyUseCard = isExtKeyUseCard;
    }

    public static String getQueryLoader() {
        return queryLoader;
    }

    public static boolean isCheckOSCCAStandards4PBC2G() {
        return checkOSCCAStandards4PBC2G;
    }

    public static boolean isCheckSM2OSCCAStandards4PBC2G() {
        return checkSM2OSCCAStandards4PBC2G;
    }

    public static void setCheckSM2OSCCAStandards4PBC2G(boolean checkSM2OSCCAStandards4PBC2G) {
        ExtendedConfigOld.checkSM2OSCCAStandards4PBC2G = checkSM2OSCCAStandards4PBC2G;
    }

    public static boolean isSubjectQuery() {
        return subjectQuery;
    }

    public static void setCheckOSCCAStandards4PBC2G(boolean checkOSCCAStandards4PBC2G) {
        ExtendedConfigOld.checkOSCCAStandards4PBC2G = checkOSCCAStandards4PBC2G;
    }

    /**
     * 设置资源同步类序列号
     * 资源同步时选择是否是patch22之前的版本还是之后的版本
     * <p>
     * 默认为新版本
     */
    private static boolean isNewSerialVersionUID = true;
    private static final String newNewSerialVersionFile = SystemInfoConsts.configPath +
            "/newSerialVersionUID.properties";
    private static final String oldNewSerialVersionFile = SystemInfoConsts.configPath +
            "/oldSerialVersionUID.properties";

    /*
     *是否开启自检日志单独存储
     * */
    private static boolean selfTest;

    /*
     *服务远程日志协议
     *
     * */
    private static String syslogProtocol;
    /*
     *服务远程日志协议是SSL时配置文件位置
     *
     * */
    private static String syslogProtocolSSLConfigPath;

    /**
     * 国密公钥运算是否使用加密卡，包括验签名和解密。（只适用于信创版本签名服务器，非信创版本不可修改）
     *
     * @20200902
     */
    private static boolean GMPublicAlgUseHSM = false;


    private static boolean asymmEncryptSyn;

    private static boolean asymmDecryptSyn;

    private static boolean decryptSupportBankCode;

    private static int encryptCardWorkingMessageQueue = 1;

    /**
     * @since 5.6.50.4 之后的项目
     * @date 2022.08.19 11.18
     * @author hoary
     * 吉大的P10编码，证书主题全都使用UTF8String
     */
    private static boolean p10SubjectJida;

    private static String pbeSalt;

    private static int pbeIteration;

    private static String pbeSKFAlg;

    private static String pbeProvider;

    private static String pbeSymmAlg;

    private static String pbeSymmIV;

    private static boolean genRandomUseCard = false;

    /**
     * 系统模式
     * mode.system = csspcloud
     * 为使此配置兼容未来可能出现的其他模式，使用string类型
     */
    private static String systemMode;


    public static boolean isGenRandomUseCard() {
        return genRandomUseCard;
    }

    public static void setGenRandomUseCard(boolean genRandomUseCard) {
        ExtendedConfigOld.genRandomUseCard = genRandomUseCard;
    }

    public static boolean isEnvelopSM4OIDUseUnStandard() {
        return envelopSM4OIDUseUnStandard;
    }

    public static void setEnvelopSM4OIDUseUnStandard(boolean envelopSM4OIDUseUnStandard) {
        ExtendedConfigOld.envelopSM4OIDUseUnStandard = envelopSM4OIDUseUnStandard;
    }

    public static boolean isUsingCSM3() {
        return isUsingCSM3;
    }

    public static void setIsUsingCSM3(boolean isUsingCSM3) {
        ExtendedConfigOld.isUsingCSM3 = isUsingCSM3;
    }

    public static String getPbeSalt() {
        return pbeSalt;
    }

    public static void setPbeSalt(String pbeSalt) {
        ExtendedConfigOld.pbeSalt = pbeSalt;
    }

    public static int getPbeIteration() {
        return pbeIteration;
    }

    public static void setPbeIteration(int pbeIteration) {
        ExtendedConfigOld.pbeIteration = pbeIteration;
    }

    public static String getPbeSKFAlg() {
        return pbeSKFAlg;
    }

    public static void setPbeSKFAlg(String pbeSKFAlg) {
        ExtendedConfigOld.pbeSKFAlg = pbeSKFAlg;
    }

    private static boolean signAndEnvelopedEncSign;

    private static boolean signAndEnvelopedDecSign;


    public static boolean isSignAndEnvelopedEncSign() {
        return signAndEnvelopedEncSign;
    }

    public static void setSignAndEnvelopedEncSign(boolean signAndEnvelopedEncSign) {
        ExtendedConfigOld.signAndEnvelopedEncSign = signAndEnvelopedEncSign;
    }

    public static boolean isSignAndEnvelopedDecSign() {
        return signAndEnvelopedDecSign;
    }

    public static void setSignAndEnvelopedDecSign(boolean signAndEnvelopedDecSign) {
        ExtendedConfigOld.signAndEnvelopedDecSign = signAndEnvelopedDecSign;
    }

    public static String getPbeProvider() {
        return pbeProvider;
    }

    public static void setPbeProvider(String pbeProvider) {
        ExtendedConfigOld.pbeProvider = pbeProvider;
    }


    public static String getPbeSymmAlg() {
        return pbeSymmAlg;
    }

    public static void setPbeSymmAlg(String pbeSymmAlg) {
        ExtendedConfigOld.pbeSymmAlg = pbeSymmAlg;
    }


    public static String getPbeSymmIV() {
        return pbeSymmIV;
    }

    public static void setPbeSymmIV(String pbeSymmIV) {
        ExtendedConfigOld.pbeSymmIV = pbeSymmIV;
    }


    public static boolean isP10SubjectJida() {
        return p10SubjectJida;
    }

    public static void setP10SubjectJida(boolean p10SubjectJida) {
        ExtendedConfigOld.p10SubjectJida = p10SubjectJida;
    }

    public static String getSyslogProtocol() {
        return syslogProtocol;
    }

    public static void setSyslogProtocol(String syslogProtocol) {
        ExtendedConfigOld.syslogProtocol = syslogProtocol;
    }

    public static String getSyslogProtocolSSLConfigPath() {
        return syslogProtocolSSLConfigPath;
    }

    public static void setSyslogProtocolSSLConfigPath(String syslogProtocolSSLConfigPath) {
        ExtendedConfigOld.syslogProtocolSSLConfigPath = syslogProtocolSSLConfigPath;
    }

    public static int getEncryptCardWorkingMessageQueue() {
        return encryptCardWorkingMessageQueue;
    }

    public static void setEncryptCardWorkingMessageQueue(int encryptCardWorkingMessageQueue) {
        ExtendedConfigOld.encryptCardWorkingMessageQueue = encryptCardWorkingMessageQueue;
    }

    public static boolean isGMPublicAlgUseHSM() {
        return GMPublicAlgUseHSM;
    }

    public static boolean isIsNewSerialVersionUID() {
        return isNewSerialVersionUID;
    }

    public static void setIsNewSerialVersionUID(boolean isNewSerialVersionUID) {
        ExtendedConfigOld.isNewSerialVersionUID = isNewSerialVersionUID;
    }

    public static boolean isSelfTest() {
        return selfTest;
    }

    public static void setSelfTest(boolean isSelfTest) {
        ExtendedConfigOld.selfTest = isSelfTest;
    }

    public static boolean isIsCheckMatch() {
        return isCheckMatch;
    }

    public static void setIsCheckMatch(boolean isCheckKeyData) {
        ExtendedConfigOld.isCheckMatch = isCheckKeyData;
    }


    public static String getSM3CertpucIDString() {
        return SM3CertpucIDString;
    }

    public static void setSM3CertpucIDString(String SM3CertpucIDString) {
        ExtendedConfigOld.SM3CertpucIDString = SM3CertpucIDString;
    }

    public static String getSM3P10PucIDString() {
        return SM3P10PucIDString;
    }

    public static void setSM3P10PucIDString(String SM3P10PucIDString) {
        ExtendedConfigOld.SM3P10PucIDString = SM3P10PucIDString;
    }

    public static String getHgfPath() {
        return hgfPath;
    }

    public static String getSM3SignpucIDString() {
        return SM3SignpucIDString;
    }

    public static void setSM3SignpucIDString(String SM3SignpucIDString) {
        ExtendedConfigOld.SM3SignpucIDString = SM3SignpucIDString;
    }

    public static String getSM3OCSPPucIDString() {
        return SM3OCSPPucIDString;
    }

    public static void setSM3OCSPPucIDString(String SM3OCSPPucIDString) {
        ExtendedConfigOld.SM3OCSPPucIDString = SM3OCSPPucIDString;
    }

    public static boolean isLock4CryptoCard() {
        return lock4CryptoCard;
    }

    public static int getThreadCount4KeyPairPool() {
        return threadCount4KeyPairPool;
    }

    public static int getSm2PoolSize() {
        return sm2PoolSize;
    }

    public static void setSm2PoolSize(int sm2PoolSize) {
        ExtendedConfigOld.sm2PoolSize = sm2PoolSize;
    }

    public static int getRsa1024PoolSize() {
        return rsa1024PoolSize;
    }

    public static void setRsa1024PoolSize(int rsa1024PoolSize) {
        ExtendedConfigOld.rsa1024PoolSize = rsa1024PoolSize;
    }

    public static int getRsa2048PoolSize() {
        return rsa2048PoolSize;
    }

    public static void setRsa2048PoolSize(int rsa2048PoolSize) {
        ExtendedConfigOld.rsa2048PoolSize = rsa2048PoolSize;
    }

    public static boolean isExtractCertFile() {
        return extractCertFile;
    }

    public static void setExtractCertFile(boolean extractCertFile) {
        ExtendedConfigOld.extractCertFile = extractCertFile;
    }

    public static boolean isLazyLoadAsymmKey() {
        return lazyLoadAsymmKey;
    }

    public static void setLazyLoadAsymmKey(boolean lazyLoadAsymmKey) {
        ExtendedConfigOld.lazyLoadAsymmKey = lazyLoadAsymmKey;
    }

    public static boolean isUseCnAndDnIndex() {
        return useCnAndDnIndex;
    }

    public static boolean isForceGC() {
        return forceGC;
    }

    public static String[] getNocheckBankid() {
        return nocheckBankid;
    }

    public static boolean isCheckSM2Pubk() {
        return isCheckSM2Pubk;
    }

    public static boolean isSendNotice() {
        return isSendNotice;
    }

    public static int getGenKeyPairGear() {
        return genKeyPairGear;
    }

    public static boolean isWangLianGenRandomKey() {
        return wanglianGenRandomKey;
    }

    public static void setWangLianGenRandomKey(boolean wanglianGenRandomKey) {
        ExtendedConfigOld.wanglianGenRandomKey = wanglianGenRandomKey;
    }

    public static long getAutoGCInterval() {
        return autoGCInterval * 60L * 1000L;
    }

    public static boolean isNeedCheckOSCCAStandards() {
        return needCheckOSCCAStandards;
    }

    public static void setNeedCheckOSCCAStandards(boolean needCheckOSCCAStandards) {
        ExtendedConfigOld.needCheckOSCCAStandards = needCheckOSCCAStandards;
    }

    public static boolean isECSigMustQ7() {
        return ECSigMustQ7;
    }

    public static void setECSigMustQ7(boolean ECSigMustQ7) {
        ExtendedConfigOld.ECSigMustQ7 = ECSigMustQ7;
    }

    public static boolean isECSignUseECAlgWithP7() {
        return ECSignUseECAlgWithP7;
    }

    public static void setECSignUseECAlgWithP7(boolean ECSignUseECAlgWithP7) {
        ExtendedConfigOld.ECSignUseECAlgWithP7 = ECSignUseECAlgWithP7;
    }

    public static boolean isSM2SigMustQ7() {
        return SM2SigMustQ7;
    }

    public static boolean isRSASigMustQ7() {
        return RSASigMustQ7;
    }

    public static boolean isSM2SigMustSeq() {
        return SM2SigMustSeq;
    }

    public static boolean isSM2SigMustUnsignedInt() {
        return SM2SigMustUnsignedInt;
    }

    public static boolean isSM2SigMustSignedInt() {
        return SM2SigMustSignedInt;
    }

    public static void setSM2SigMustQ7(boolean sM2SigMustQ7) {
        ExtendedConfigOld.SM2SigMustQ7 = sM2SigMustQ7;
    }

    public static void setRSASigMustQ7(boolean rSASigMustQ7) {
        ExtendedConfigOld.RSASigMustQ7 = rSASigMustQ7;
    }

    public static void setSM2SigMustSeq(boolean sM2SigMustSeq) {
        ExtendedConfigOld.SM2SigMustSeq = sM2SigMustSeq;
    }

    public static void setSM2SigMustUnsignedInt(boolean sM2SigMustUnsignedInt) {
        ExtendedConfigOld.SM2SigMustUnsignedInt = sM2SigMustUnsignedInt;
    }

    public static void setSM2SigMustSignedInt(boolean sM2SigMustSignedInt) {
        ExtendedConfigOld.SM2SigMustSignedInt = sM2SigMustSignedInt;
    }

    public static boolean isIssuerDNCaseMatch() {
        return isIssuerDNCaseMatch;
    }

    public static boolean isSupportIssuerKid() {
        return isSupportIssuerKid;
    }

    public static boolean isVerifyCertChain() {
        return isVerifyCertChain;
    }

    public static boolean isCacheCert() {
        return isCacheCert;
    }

    public static String getAccessFac() {
        return syslogAccess;
    }

    public static String getAlgMode() {
        return algMode;
    }

    public static int getBackLog() {
        return backLog;
    }

    public static int[] getCrlCleanTimes() {
        return crlCleanTimes;
    }

    public static String getCRLLoadMode() {
        return crlLoadMode;
    }

    public static String getDebugFac() {
        return syslogDebug;
    }

    public static String getDecryptGear() {
        return decryptGear;
    }

    public static String getDecryptProvider() {
        return decryptProvider;
    }

    public static String getDefaultSM2P10Alg() {
        return defaultSM2P10Alg;
    }

    public static String getEncoding() {
        return encoding;
    }

    public static String getEncryptGear() {
        return encryptGear;
    }

    public static String getEncryptProvider() {
        return encryptProvider;
    }

    public static int getEnvelopCacheSize() {
        return envelopCacheSize;
    }

    public static int getGenRSA2048ThreadCount() {
        return genRSA2048ThreadCount;
    }

    public static void setGenRSA2048ThreadCount(int genRSA2048ThreadCount) {
        ExtendedConfigOld.genRSA2048ThreadCount = genRSA2048ThreadCount;
    }

    public static int getGenRSA2048PoolSize() {
        return genRSA2048PoolSize;
    }

    public static void setGenRSA2048PoolSize(int genRSA2048PoolSize) {
        ExtendedConfigOld.genRSA2048PoolSize = genRSA2048PoolSize;
    }

    public static int getGenRSA1024PoolSize() {
        return genRSA1024PoolSize;
    }

    public static void setGenRSA1024PoolSize(int genRSA1024PoolSize) {
        ExtendedConfigOld.genRSA1024PoolSize = genRSA1024PoolSize;
    }

    public static int getGenRSA1024ThreadCount() {
        return genRSA1024ThreadCount;
    }

    public static void setGenRSA1024ThreadCount(int genRSA1024ThreadCount) {
        ExtendedConfigOld.genRSA1024ThreadCount = genRSA1024ThreadCount;
    }

    public static String getJmxMonitorLevel() {
        if (!jmxMonitorLevel.equals(JMX_MONITOR_LEVEL_NONE) && !jmxMonitorLevel.equals(JMX_MONITOR_LEVEL_SYSTEM)
                && !jmxMonitorLevel.equals(JMX_MONITOR_LEVEL_FULL)) {
            jmxMonitorLevel = JMX_MONITOR_LEVEL_NONE;
        }
        return jmxMonitorLevel;
    }

    public static String getWechartstockEncpassword() {
        return wechartstockEncpassword;
    }

    public static void setWechartstockEncpassword(
            String wechartstockEncpassword) {
        ExtendedConfigOld.wechartstockEncpassword = wechartstockEncpassword;
    }

    public static long getLongBusinessTime() {
        return longBusinessTime;
    }

    public static int getMaxReadThread() {
        return maxReadThread;
    }

    public static int getMaxSessionPoolSize() {
        return maxSessionPoolSize;
    }

    public static int[] getPDFPermissions() {
        return pdfPermissions;
    }

    private static int getPermissionValue(String str) {
        if ("ASSEMBLY".equalsIgnoreCase(str)) {
            return PDF_ALLOW_ASSEMBLY;
        }
        if ("COPY".equalsIgnoreCase(str)) {
            return PDF_ALLOW_COPY;
        }
        if ("DEGRADED_PRINTING".equalsIgnoreCase(str)) {
            return PDF_ALLOW_DEGRADED_PRINTING;
        }
        if ("FILL_IN".equalsIgnoreCase(str)) {
            return PDF_ALLOW_FILL_IN;
        }
        if ("MODIFY_ANNOTATIONS".equalsIgnoreCase(str)) {
            return PDF_ALLOW_MODIFY_ANNOTATIONS;
        }
        if ("MODIFY_CONTENTS".equalsIgnoreCase(str)) {
            return PDF_ALLOW_MODIFY_CONTENTS;
        }
        if ("PRINTING".equalsIgnoreCase(str)) {
            return PDF_ALLOW_PRINTING;
        }
        if ("SCREENREADERS".equalsIgnoreCase(str)) {
            return PDF_ALLOW_SCREENREADERS;
        }
        return -1;
    }

    public static String getPrivateKeyAlg() {
        return privateKeyAlg;
    }

    public static int getProjectID() {
        return projectID;
    }

    public static long getReloadCRLInterval() {
        return reloadCRLInterval;
    }

    public static long getResourceReloadInterval() {
        return resourceReloadInterval;
    }

    public static long getServiceInfoCollectInterval() {
        return serviceInfoCollectInterval;
    }

    public static String getShellFile(String name) {
        return loadString(name, "");
    }

    public static String getSignNotation() {
        return signNotation;
    }

    public static boolean isDecryptSupportBankCode() {
        return decryptSupportBankCode;
    }


    public static String getSignProvider() {
        if (signProviders != null) {
            synchronized (signProviderLock) {
                if (signProviderWheel < 0) {
                    signProviderWheel = 0;
                }
                int i = (int) signProviderWheel % signProviders.length;
                signProviderWheel++;
                return signProviders[i];
            }
        } else {
            return signProvider;
        }
    }

    public static int getSm2CacheSize() {
        return sm2CacheSize;
    }

    public static String getSm2Provider() {
        return sm2Provider;
    }

    public static String getSm2SignGear() {
        return sm2SignGear;
    }

    public static String getSm2VerifyGear() {
        return sm2VerifyGear;
    }

    public static byte[] getSM3OCSPPucid() {
        return SM3OCSPPucID;
    }

    public static byte[] getSm3P10Puid() {
        return SM3P10PucID;
    }

    public static byte[] getSM3pucID() {
        return SM3CertpucID;
    }

    public static byte[] getSM3SignpucID() {
        return SM3SignpucID;
    }

    public static String getStampFile() {
        return stampFile;
    }

    /**
     * ---2013-12-05(create) LH.
     *
     * @return
     */
    public static String getSubFilter() {
        /*
         * @since 5.5.40.9
         */
        return subFilter;
    }

    public static String getSystemFac() {
        return syslogSystem;
    }

    public static int getTaskQueueMax() {
        return taskQueueMax;
    }

    public static long getQueryTime() {
        return queryTime;
    }

    public static void setQueryTime(long queryTime) {
        ExtendedConfigOld.queryTime = queryTime;
    }

    public static long getTaskQueueWatchInterval() {
        return taskQueueWatchInterval;
    }

    public static int getThreadPoolQueue() {
        return threadPoolQueue;
    }

    public static String getVerifyProvider() {
        if (verifyProviders != null) {
            synchronized (verifyProviderLock) {
                if (verifyProviderWheel < 0) {
                    verifyProviderWheel = 0;
                }
                int i = (int) verifyProviderWheel % verifyProviders.length;
                verifyProviderWheel++;
                return verifyProviders[i];
            }
        } else {
            return verifyProvider;
        }
    }

    public static boolean isP10CFCAWithAttibute() {
        return p10CFCAWithAttibute;
    }

    public static void setP10CFCAWithAttibute(boolean p10CFCAWithAttibute) {
        ExtendedConfigOld.p10CFCAWithAttibute = p10CFCAWithAttibute;
    }

    public static boolean isAutoReloadResources() {
        return isAutoReloadResources;
    }

    public static boolean isAutoUnzip() {
        return isAutoUnzip;
    }

    public static boolean isCatchHandler() {
        return isCatchHandler;
    }

    public static boolean isCheckBankID() {
        return isCheckBankID;
    }

    public static boolean isCheckCertValidity() {
        return isCheckCertValidity;
    }

    public static boolean isDebug() {
        return isDebug;
    }

    public static boolean isEnvelopCache() {
        return envelopCache;
    }

    public static boolean isInBlackList() {
        return inBlackList;
    }

    public static boolean isIntegerUnsigned() {
        return integerUnsigned;
    }
    /**
     *  增加CRL服务器健康检查属性
     *
     * @author zhaoxin
     * @since 2021/09/08
     */
    /**
     * 启用健康检查
     */
    private static boolean enableHealthCheck;
    /**
     * 检查间隔
     */
    private static int checkInterval;
    /**
     * 连接超时
     */
    private static int connTimeout;
    /**
     * 读取超时
     */
    private static int readTimeout;
    /**
     * 重试此时
     */
    private static int retryCount;

    /**
     * @return 产生P10 时候的空节点是否保留。true保留，false不保留
     * 适用于RSA
     * @author Hoary.Huang
     * @since 5.5.40.16 2020.12.30
     */
    public static boolean isP10RsaWithNull() {
        return p10RsaWithNull;
    }

    /**
     * @return 产生P10 时候的空节点是否保留。true保留，false不保留
     * 适用于 SM2
     * @author Hoary.Huang
     * @since 5.5.40.16 2020.12.30
     */
    public static boolean isP10Sm2WithNull() {
        return p10Sm2WithNull;
    }

    public static boolean isKLBSignOuterFields() {
        return KLBSignOuterFields;
    }

    public static boolean isLogRespTime() {
        return isLogRespTime;
    }

    public static boolean isPrintST() {
        return isPrintST;
    }

    public static boolean isReturnSignResult() {
        return isReturnSignResult;
    }

    public static boolean isReturnVerifyResult() {
        return isReturnVerifyResult;
    }

    public static boolean isRsaEncUsingQ7() {
        return rsaEncUsingQ7;
    }

    public static boolean isRSASignUsingQ7() {
        return rsaSignUsingQ7;
    }

    public static boolean isSave() {
        return isSave;
    }

    public static boolean isSessionMonitorOpen() {
        return isSessionMonitorOpen;
    }

    public static boolean isSm2Cache() {
        return sm2Cache;
    }

    public static boolean isSm2EncUsingQ7() {
        return sm2EncUsingQ7;
    }

    public static boolean isSM2SignUsehardalg() {
        return sm2SignUseHardALG;
    }

    public static boolean isSM2SignUsingQ7() {
        return sm2SignUsingQ7;
    }

    public static boolean isSM2VerifyUsehardalg() {
        return sm2VerifyUseHardALG;
    }

    public static boolean isSupportsm2() {
        return supportsm2;
    }

    public static boolean isUsehardkeystore() {
        return sm2UseHardKeyStore;
    }

    public static boolean isUsingCImp() {
        return isUsingCImp;
    }

    public static void setUsingCImp(boolean usec) {
        isUsingCImp = usec;
    }

    public static boolean isWithCertChain() {
        return withCertChain;
    }

    public static long getIntervalMaximum() {
        return intervalMaximum;
    }

    public static void setIntervalMaximum(long intervalMaximum) {
        ExtendedConfigOld.intervalMaximum = intervalMaximum;
    }

    public static long getIntervalMinimum() {
        return intervalMinimum;
    }

    public static void setIntervalMinimum(long intervalMinimum) {
        ExtendedConfigOld.intervalMinimum = intervalMinimum;
    }

    public static boolean isP7WithNull() {
        return p7WithNull;
    }

    public static void setP7WithNull(boolean p7WithNull) {
        ExtendedConfigOld.p7WithNull = p7WithNull;
    }

    public static void load(String confFile) {
        prop = new Properties();
        try {
            FileInputStream in = new FileInputStream(confFile);
            InputStreamReader isr = new InputStreamReader(in, "GBK");
            BufferedReader bf = new BufferedReader(isr);
            prop.load(bf);
            prop.list(System.out);

            isDebug = loadBoolean("isdebug", false);
            CryptoUtil.debug = isDebug;
            cn.com.infosec.netsign.der.util.ConsoleLogger.isDebug = isDebug;

            // 2020-06-11 为isfj中的日志debug赋值
            cn.com.infosec.util.ConsoleLogger.isDebug = isDebug;

            isPrintST = loadBoolean("isprintst", true);

            isSave = loadBoolean("issave", false);

            nohupLogConfig = loadString("nohuplogconfig", null);

            threadPoolCore = loadInt("threadpoolcore", 50);

            threadPoolMax = loadInt("threadpoolmax", 500);

            threadPoolQueue = loadInt("threadpoolqueue", 30000);

            isCatchHandler = loadBoolean("iscatchhandler", false);

            logBuffer = loadInt("logbuffer", 0);

            syslogSystem = loadString("syslogsystem", syslogSystem);

            syslogAccess = loadString("syslogaccess", syslogAccess);

            syslogDebug = loadString("syslogdebug", syslogDebug);

            isCheckCertValidity = loadBoolean("checkvalidity", true);

            encoding = loadString("encoding", "ISO8859-1");

            jmxMonitorLevel = loadString("jmlevel", JMX_MONITOR_LEVEL_NONE);

            taskQueueMax = loadInt("tqmax", 2000);
            queryTime = loadLong("queryTime", 10000);
            intervalMaximum = loadLong("intervalMaximum", 9223372036854775807L);
            intervalMinimum = loadLong("intervalMinimum", -9223372036854775808L);

            backLog = loadInt("backlog", 200);
            taskQueueWatchInterval = loadLong("tqwinterval", 50);

            serviceInfoCollectInterval = loadLong("sicinterval", 60000);

            projectID = loadInt("projectid", 0);

            maxReadThread = loadInt("maxreadthread", 3);

            algMode = loadString("algmode", "soft");

            verifyProvider = loadString("verifyprovider", "INFOSEC");
            if (verifyProvider.indexOf(",") > 0) {
                verifyProviders = verifyProvider.split(",");
                verifyProvider = verifyProviders[0];
            }

            signProvider = loadString("signprovider", "INFOSEC");
            if (signProvider.indexOf(",") > 0) {
                signProviders = signProvider.split(",");
                signProvider = signProviders[0];
            }

            encryptProvider = loadString("encryptprovider", "INFOSEC");

            decryptProvider = loadString("decryptprovider", "INFOSEC");

            symmProvider = loadString("symm.provider", "INFOSEC");


            // ---2013-12-05 LH.
            subFilter = loadString("subFilter", "adbe.pkcs7.detached");

            signNotation = loadString("signnotation", signNotation);

            stampFile = loadString("stampfile", stampFile);

            String pdfP = loadString("pdfpermission", "");
            if (!"".equals(pdfP.trim())) {
                String[] pieces = pdfP.split(",");
                pdfPermissions = new int[1];
                for (String piece : pieces) {
                    int r = getPermissionValue(piece);
                    if (r > 0) {
                        pdfPermissions[0] |= r;
                    }
                }
            }

            inBlackList = loadBoolean("inblacklist", false);

            crlCleanTimes = loadCrlCleanTimes();

            reloadCRLInterval = loadLong("reloadcrlinterval", 300000);

            crlLoadMode = loadString("crlloadmode", "all");

            supportsm2 = loadBoolean("supportsm2", false);

            useHardKeyStore = loadBoolean("usehardkeystore", false);
            sm2UseHardKeyStore = useHardKeyStore;

            privateKeyAlg = loadString("hardkeystore.privatekeyalg", null);

            loadSM2UseHardAlg();

            sm2Provider = loadString("algprovider", null);

            sm2Provider = "".equals(sm2Provider) ? null : sm2Provider;

            defaultSM2P10Alg = loadString("defaultsm2p10alg", "SM3withSM2");

            SM3CertpucID = loadByteArray("sm3pucid", null);
            SM3CertpucIDString = loadString("sm3pucid", "");

            SM3SignpucID = loadByteArray("sm3signpucid", null);
            SM3SignpucIDString = loadString("sm3signpucid", "");

            SM3P10PucID = loadByteArray("sm3p10puid", null);
            SM3P10PucIDString = loadString("sm3p10puid", "");

            SM3OCSPPucID = loadByteArray("sm3ocspucid", null);
            SM3OCSPPucIDString = loadString("sm3ocspucid", "");

            sm2Cache = loadBoolean("sm2cache", false);

            sm2CacheSize = loadInt("sm2cachesize", 0);

            sm2SignGear = loadString("sm2signgear", "0/1");

            sm2VerifyGear = loadString("sm2verifygear", "0/1");

            envelopCache = loadBoolean("envelopcache", false);
            envelopCacheSize = loadInt("envelopcachesize", 0);
            encryptGear = loadString("encryptgear", "0/1");
            decryptGear = loadString("decryptgear", "0/1");

            withCertChain = loadBoolean("withcertchain", false);

            isAutoReloadResources = loadBoolean("isautoreloadresources", false);

            resourceReloadInterval = loadLong("resourcereloadinterval", 60 * 60 * 1000);

            isAutoUnzip = loadBoolean("isautounzip", false);

            isReturnVerifyResult = loadBoolean("isreturnverifyresult", true);

            isReturnSignResult = loadBoolean("isreturnsignresult", true);

            isSessionMonitorOpen = loadBoolean("issessionmonitoropen", false);

            maxSessionPoolSize = loadInt("maxsessionpoolsize", 10240);

            p7VerifySupportAuthAttrs = loadBoolean("p7verifysupportauthattrs", true);
            p7verifyWithLength = loadBoolean("p7verifywithlength", false);

            rsaSignUsingQ7 = loadBoolean("rsasignusingq7", false);

            sm2SignUsingQ7 = loadBoolean("sm2signusingq7", true);

            rsaEncUsingQ7 = loadBoolean("rsaencusingq7", false);

            ecEncUsingQ7 = loadBoolean("ecencusingq7", false);

            sm2EncUsingQ7 = loadBoolean("sm2encusingq7", true);

            isUsingCImp = loadBoolean("encryptusec", false);

            integerUnsigned = loadBoolean("integerunsigned", true);

            p10RsaWithNull = loadBoolean("p10.rsa.null", true);

            p10Sm2WithNull = loadBoolean("p10.sm2.null", true);

            isLogRespTime = loadBoolean("islogresponsetime", true);

            longBusinessTime = loadLong("longbusinesstime", 500);

            isCheckBankID = loadBoolean("ischeckbankid", true);

            KLBSignOuterFields = loadBoolean("klbsignouterfields", true);

            hardKeyStoreDevice = loadString("hardkeystore.device", null);

            hardKeyStroreBackupPassword = loadString("hardkeystore.backuppassword", null);

            checkWeekAlg = loadBoolean("checkweekalg", true);

            isCacheCert = loadBoolean("iscachecert", true);

            isVerifyCertChain = loadBoolean("isverifycertchain", true);

            isSupportIssuerKid = loadBoolean("issupportissuerkid", true);

            isIssuerDNCaseMatch = loadBoolean("isissuerdncasematch", true);

            SM2SigMustQ7 = loadBoolean("sm2sigmustq7", false);

            ECSigMustQ7 = loadBoolean("ecsigmustq7", false);
            ECSignUseECAlgWithP7 = loadBoolean("ecsignuseecalgwithp7", false);
            RSASigMustQ7 = loadBoolean("rsasigmustq7", false);

            SM2SigMustSeq = loadBoolean("sm2sigmustseq", false);

            SM2SigMustUnsignedInt = loadBoolean("sm2sigmustunsignedint", false);

            SM2SigMustSignedInt = loadBoolean("sm2sigmustsignedint", false);

            needCheckOSCCAStandards = loadBoolean("needcheckosccastandards", false);

            /**
             * @since 合并微信开户 项目
             */
            wechartstockEncpassword = loadString("wcsencpassword", "123456");

            genRSA1024PoolSize = loadInt("genrsa1024poolsize", 0);

            genRSA1024ThreadCount = loadInt("genrsa1024threadcount", 0);

            genRSA2048PoolSize = loadInt("genrsa2048poolsize", 0);

            genRSA2048ThreadCount = loadInt("genrsa2048threadcount", 0);


            /*
             * @since 5.5.40.5
             */
            if (NetSignImpl.PROVIDER_SWXA_ALG.equals(ExtendedConfigOld.getPrivateKeyAlg())
                    && ExtendedConfigOld.isUsehardkeystore() && (ExtendedConfigOld.getHardKeyStoreDevice() == null)) {
                signProvider = NetSignImpl.PROVIDER_SWXA;
            }

            /*
             * @since 5.5.40.5
             */
            if (NetSignImpl.PROVIDER_SWXA_ALG.equals(ExtendedConfigOld.getPrivateKeyAlg())
                    && (ExtendedConfigOld.isUsehardkeystore()) && (ExtendedConfigOld.getHardKeyStoreDevice() == null)) {
                decryptProvider = NetSignImpl.PROVIDER_SWXA;
            }

            autoGCInterval = loadInt("autogcinterval", 0);
            forceGC = loadBoolean("forcegc", false);

            oldGenUsedRatio = loadInt("oldgenusedratio", 0);

            wanglianGenRandomKey = loadBoolean("wangliangenrandomkey", false);

            // 黑龙江CA: 添加非对称密钥的延迟加载 since patch31 project 2019.10.15
            lazyLoadAsymmKey = loadBoolean("lazy.load.asymm.key", true);
            // 黑龙江CA: 证书文件进行单独存储 since patch31 project 2019.10.15
            extractCertFile = loadBoolean("extract.cert.file", false);
            // 黑龙江CA : keypair列表 使用DN和CN作为index
            useCnAndDnIndex = loadBoolean("use.dn.and.cn.index", true);


            //产生真实场景证书秘钥对。为所有秘钥对的1/n
            genKeyPairGear = loadInt("genkeypairgear", 1);
            genKeyPairGear = Math.max(genKeyPairGear, 1);

            isDeleteRAWCert = loadBoolean("isDeleteRAWCert", true);

            isSendNotice = loadBoolean("issendnotice", false);

            isCheckSM2Pubk = loadBoolean("ischecksm2pubk", true);

            String tmp = loadString("nocheckbankid", "ECDS");
            nocheckBankid = tmp.split(",");
            // 兴业银行加密库路径 2020-03-30
            libIndustrialBankCryptoPath = loadString("lib.industrial.bank.crypto.path", null);

            // 浦发银行新加密钥池，默认不开启 since patch32.1 2019-12-12
            sm2PoolSize = loadInt("sm2.pool.size", 0);
            rsa1024PoolSize = loadInt("rsa1024.pool.size", 0);
            rsa2048PoolSize = loadInt("rsa2048.pool.size", 0);
            threadCount4KeyPairPool = loadInt("thread.count.4.keypair.pool", 1);

            // hoary add at 2020.04.22
            BasicLogConfig logConfig =
                    BasicLogConfig.create().withPrintST(isPrintST).withDebug(isDebug).withSave(isSave)
                            .withNohupConfig(nohupLogConfig).withProjectID(projectID)
                            .withLogBuffer(logBuffer);
            BasicConfigManager.setLogConfig(logConfig);
            BasicExtensionConfig bec = BasicConfigManager.getBasicExtensionConfig();
            copyConfig2Basic(bec);
            BasicConfigManager.setBasicExtensionConfig(bec);

            /*
             * 是否开启加密卡同步锁 默认开启
             */
            lock4CryptoCard = loadBoolean("lock4cryptocard", true);

            snWith0 = loadBoolean("cert.sn.with0", false);

            /**
             * 2021.01.07
             * Hoary.Huang
             * 是否开启 SDF 模式
             */
            sdfMode = loadBoolean("mode.sdf", false);

            /*
             * 加密机版本 导入/生成对称密钥是否检查密钥、算法的正确性、导入非对称密钥是否检查密钥对
             * */
            isCheckMatch = loadBoolean("ischeckmatch", false);

            /*
             * 是否是新版本资源同步
             * */
            isNewSerialVersionUID = loadBoolean("isnewserialversionuid", true);
            setSerialVersionUID(isNewSerialVersionUID);

            /*
             *自检日志是否单独存储
             */
            selfTest = loadBoolean("isselftest", false);

            /*
             * 是否使用加密卡做国密公钥运算，包括验签名和解密。
             * */
            GMPublicAlgUseHSM = loadBoolean("gmpublicalgusehsm", false);

            encryptCardWorkingMessageQueue = loadInt("encryptcardworkingmessagequeue", 1);
            /**
             * 加密证书验签
             */
            encCertForSign = loadBoolean("enc.cert.for.sign", false);

            /**
             * 非对称加密是否同步， 默认不同步
             */
            asymmEncryptSyn = loadBoolean("asymm.encrypt.syn", false);

            /**
             * 非对称解密是否同步，默认不同步
             */
            asymmDecryptSyn = loadBoolean("asymm.decrypt.syn", false);

            decryptSupportBankCode = loadBoolean("asymm.decrypt.support.bank.code", true);


            //财政部：解数字信封时是否验证书，默认false

            decryptEnvelopeCheckCert = loadBoolean("decrypt.enveloped.check.cert", false);

            /**
             *  增加CRL服务器健康检查属性
             *
             * @author zhaoxin
             * @since 2021/09/08
             */
            /*
             * 功能设计不合理，如需要此功能需对这些参数做单独配置，不能放在这里
             * */
           /* checkInterval=loadInt("checkinterval",60);
            connTimeout=loadInt("conntimeout",3000);
            readTimeout=loadInt("readtimeout",3000);
            retryCount=loadInt("retrycount",3);
            enableHealthCheck=loadBoolean("enablehealthcheck",true);*/

            p7WithNull = loadBoolean("p7.discard.null", false);

            hgfPath = loadString("yun.config.path", null);

            p10SubjectJida = loadBoolean("p10.subject.encode.jida", false);

            queryLoader = loadString("query.loader", "default");
            subjectQuery = loadBoolean("subject.query", false);
            pbeSKFAlg = loadString("pbe.SKF.alg", "PBEWithSHA256And256BitAES-CBC-BC");
            pbeSalt = loadString("pbe.salt", "PBESalt");
            pbeIteration = loadInt("pbe.iteration", 10);
            pbeProvider = loadString("pbe.provider", "INFOSEC");
            pbeSymmAlg = loadString("pbe.symm.alg", "AES/CBC/PKCS7Padding");
            pbeSymmIV = loadString("pbe.symm.IV", "1234567812345678");
            synBatch = loadBoolean("start.syn.batch", true);

            p10CFCAWithAttibute = loadBoolean("p10.cfca.p9Attribute", false);
            checkOSCCAStandards4PBC2G = loadBoolean("check.oscca.standards", false);
            checkSM2OSCCAStandards4PBC2G = loadBoolean("check.sm2.oscca.standards", true);


            isExtKeyUseCard = loadBoolean("external.key.operation.crypto.card", true);
            isUsingCSM3 = loadBoolean("useCwithSM3", false);
            synScheduledServiceTimeOut = loadLong("syn.scheduled.service.timeout", 15000);
            genRandomUseCard = loadBoolean("genrandomusecard", false);
            // add since 2024.02.22 农信银增加cavium验签失败时候使用软验签 useSoftWhenCaviumUnavailable
            caviumUseSoftWhenFailed = loadBoolean("cavium.use.soft.when.unavailable", false);
            add2CaviumSystemProperty(String.valueOf(caviumUseSoftWhenFailed));
            /**
             *  增加CRL服务器健康检查属性
             *
             * @author zhaoxin
             * @since 2021/09/08
             */
            checkInterval = loadInt("checkinterval", 60);
            connTimeout = loadInt("conntimeout", 3000);
            readTimeout = loadInt("readtimeout", 3000);
            retryCount = loadInt("retrycount", 3);
            enableHealthCheck = loadBoolean("enablehealthcheck", true);
            regenerateCryptoTextForSM2 = loadBoolean("regenerateCryptoTextForSM2", false);
            isRecordingStartTime = loadBoolean("isrecordingstarttime", false);

            envelopSM4OIDUseUnStandard= loadBoolean("envelopsm4oiduseunstandard", false);

            systemMode = loadString("mode.system", null);
            ServerConfig.setCsspCloudMode("csspcloud".equals(systemMode));

            // 关闭流操作 ---------------------------------------------
            in.close();
            bf.close();
            isr.close();
        } catch (Exception e) {
            ConsoleLogger.logException(e);
        }
    }

    private static void setSerialVersionUID(boolean isNewSerialVersionUID) {
        if (versionConfig == null) {
            versionConfig = new SerialVersionConfig();
        }
        Properties prop = new Properties();
        FileInputStream in = null;
        try {
            if (isNewSerialVersionUID) {
                in = new FileInputStream(newNewSerialVersionFile);
            } else {
                in = new FileInputStream(oldNewSerialVersionFile);
            }
            prop.load(in);
            prop.list(System.out);
            versionConfig.setRawCertSynEmissaryUID(loadRawCertSynEmissaryUID(prop));
            versionConfig.setSynEmissaryUID(loadSynEmissaryUID(prop));
            versionConfig.setSynParametersUID(loadSynParametersUID(prop));
            versionConfig.setSynResultUID(loadSynResultUID(prop));
        } catch (IOException e) {
            ConsoleLogger.logString("no file found: configs/webuiConfig/newSerialVersionUID.properties");
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }
        }

    }

    private static void copyConfig2Basic(BasicExtensionConfig bec) {
        bec.setRsaSignUsingQ7(rsaSignUsingQ7);
        bec.setRsaEncUsingQ7(rsaEncUsingQ7);
        bec.setSm2SignUsingQ7(sm2SignUsingQ7);
        bec.setSm2EncUsingQ7(sm2EncUsingQ7);
    }

    public static boolean isIsCollectData() {
        return isCollectData;
    }

    public static void setIsCollectData(boolean isCollectData) {
        ExtendedConfigOld.isCollectData = isCollectData;
    }

    public static String getNohupLogConfig() {
        return nohupLogConfig;
    }

    public static String setNohupLogConfig(String config) {
        return nohupLogConfig = config;
    }

    public static boolean loadBoolean(String name, boolean defValue) {
        try {
            String str = prop.getProperty(name).trim().toUpperCase();
            return ("TRUE".equals(str) || "YES".equals(str));
        } catch (Exception e) {
            return defValue;
        }
    }

    private static byte[] loadByteArray(String name, byte[] defValue) {
        try {
            String str = prop.getProperty(name).trim();
            if (str.startsWith("base64,")) {
                str = str.substring(7);
                return Base64.decode(str);
            } else {
                return str.getBytes("GBK");
            }
        } catch (Exception e) {
            return defValue;
        }
    }

    private static int[] loadCrlCleanTimes() {
        String timesStr = loadString("crlcleantimes", "2");
        ConsoleLogger.logString("crlcleantimes:" + timesStr);
        try {
            String[] pieces = timesStr.split(",");
            int[] times = new int[pieces.length];
            for (int i = 0, length = pieces.length; i < length; i++) {
                times[i] = Integer.parseInt(pieces[i]);
            }
            return times;
        } catch (Exception e) {
            return new int[]{2};
        }
    }

    private static int loadInt(String name, int defValue) {
        try {
            String str = prop.getProperty(name).trim();
            return Integer.parseInt(str);
        } catch (Exception e) {
            return defValue;
        }
    }

    private static long loadLong(String name, long defValue) {
        try {
            String str = prop.getProperty(name).trim();
            return Long.parseLong(str);
        } catch (Exception e) {
            return defValue;
        }
    }

    private static void loadSM2UseHardAlg() {
        String tmp = loadString("usehardalg", "NO").toUpperCase();
        if (tmp.indexOf(",") > 0) {
            String[] pieces = tmp.split(",");
            sm2SignUseHardALG = ("YES".equals(pieces[0]) || "TRUE".equals(pieces[0]));
            sm2VerifyUseHardALG = ("YES".equals(pieces[1]) || "TRUE".equals(pieces[1]));
        } else {
            sm2SignUseHardALG = sm2VerifyUseHardALG = ("YES".equals(tmp) || "TRUE".equals(tmp));
        }
    }

    private static String loadString(String name, String defValue) {
        try {
            return prop.getProperty(name).trim();
        } catch (Exception e) {
            return defValue;
        }
    }

    public static int logBuffer() {
        return logBuffer;
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        ExtendedConfigOld.load("d:/extension.properties");
        System.out.println("---- " + ExtendedConfigOld.getNohupLogConfig());
    }

    public static boolean p7VerifySupportAuthAttrs() {
        return p7VerifySupportAuthAttrs;
    }

    public static boolean isP7verifyWithLength() {
        return p7verifyWithLength;
    }

    public static void setP7verifyWithLength(boolean p7verifyWithLength) {
        ExtendedConfigOld.p7verifyWithLength = p7verifyWithLength;
    }

    public static void setAlgMode(String algMode) {
        ExtendedConfigOld.algMode = algMode;
    }

    public static void setAutoUnzip(boolean isAutoUnzip) {
        ExtendedConfigOld.isAutoUnzip = isAutoUnzip;
    }

    public static String getSymmProvider() {
        return symmProvider;
    }

    public static void setSymmProvider(String symmProvider) {
        ExtendedConfigOld.symmProvider = symmProvider;
    }

    /**
     * 兴业银行加密库路径
     * 2020/03/30
     */
    private static String libIndustrialBankCryptoPath;

    public static String getLibIndustrialBankCryptoPath() {
        return libIndustrialBankCryptoPath;
    }

    public static void setDecryptProvider(String decryptProvider) {
        ExtendedConfigOld.decryptProvider = decryptProvider;
    }

    public static void setEncoding(String encodName) {
        ExtendedConfigOld.encoding = encodName;
    }

    public static void setEncryptProvider(String encryptProvider) {
        ExtendedConfigOld.encryptProvider = encryptProvider;
    }

    public static void setSignNotation(String signNotation) {
        ExtendedConfigOld.signNotation = signNotation;
    }

    public static void setSignProvider(String signProvider) {
        ExtendedConfigOld.signProvider = signProvider;
    }

    public static void setSM3OCSPPucid(byte[] id) {
        SM3OCSPPucID = id;
    }

    public static void setSm3P10Puid(byte[] puid) {
        SM3P10PucID = puid;
    }

    public static void setSM3SignpucID(byte[] id) {
        SM3SignpucID = id;
    }

    public static void setStampFile(String stampFile) {
        ExtendedConfigOld.stampFile = stampFile;
    }

    public static void setVerifyProvider(String verifyProvider) {
        ExtendedConfigOld.verifyProvider = verifyProvider;
    }

    public static int threadPoolCore() {
        return threadPoolCore;
    }

    public static int threadPoolMax() {
        return threadPoolMax;
    }

    public static String getHardKeyStoreDevice() {
        return hardKeyStoreDevice;
    }

    public static void setHardKeyStoreDevice(String devicename) {
        hardKeyStoreDevice = devicename;
    }

    public static String getHardKeyStoreBackupPassword() {
        return hardKeyStroreBackupPassword;
    }

    public static boolean isCheckWeekAlg() {
        return checkWeekAlg;
    }

    public static void setDeleteRAWCert(boolean isDeleteRAWCert) {
        ExtendedConfigOld.isDeleteRAWCert = isDeleteRAWCert;
    }

    public static boolean isDeleteRAWCert() {
        return isDeleteRAWCert;
    }

    public static boolean isSnWith0() {
        return snWith0;
    }

    public static void setSnWith0(boolean snWith0) {
        ExtendedConfigOld.snWith0 = snWith0;
    }

    public static boolean isSdfMode() {
        return sdfMode;
    }

    /**
     * @return
     * @since bjcp1.1
     */
    public static boolean isEnvelopSignerIDUserKid() {
        return envelopeSignerIDUseKid;
    }

    /**
     * @param on
     * @since bjcp1.1
     */
    public static void setEnvelopSignerIDUserKid(boolean on) {
        envelopeSignerIDUseKid = on;
    }

    public static void setOldGenUsedRatio(int oldGenUsedRatio) {
        ExtendedConfigOld.oldGenUsedRatio = oldGenUsedRatio;
    }

    public static int getOldGenUsedRatio() {
        return oldGenUsedRatio;
    }

    public static boolean isAsymmEncryptSyn() {
        return asymmEncryptSyn;
    }

    public static boolean isAsymmDecryptSyn() {
        return asymmDecryptSyn;
    }


    /**
     * 拼接字符串，生成extension.properties
     *
     * 这是服务高级配置页面保存用到的函数, 只保存一项
     * @param filepath
     */
    public synchronized static void save(String filepath, String configName, String configValue) {

        Reader reader = null;
        try {
            reader = new InputStreamReader(new FileInputStream(filepath), "GBK");
            prop.load(reader);
            prop.setProperty(configName, configValue);

            StringBuilder buf = new StringBuilder();
            buf.append("##########IO Properties##################################\n");
            buf.append("backlog=").append(loadInt("backlog", 200)).append("\n");
            buf.append("#if open the session monitor thread to close the idle connections\n");
            buf.append("issessionmonitoropen=").append(loadBoolean("issessionmonitoropen", false)).append("\n");
            buf.append("#max sessions the monitor carries\n");
            buf.append("maxsessionpoolsize=").append(loadInt("maxsessionpoolsize", 10240)).append("\n");
            buf.append("\n");

            buf.append("##########Thread Pool Properties##########################\n");
            buf.append("#count of core thread of the threadpool\n");
            buf.append("threadpoolcore=").append(loadInt("threadpoolcore", 50)).append("\n");
            buf.append("#max count of thread of the threadpool\n");
            buf.append("threadpoolmax=").append(loadInt("threadpoolmax", 500)).append("\n");
            buf.append("threadpoolqueue=").append(loadInt("threadpoolqueue", 30000)).append("\n");
            buf.append("#if catch the handler for close them\n");
            buf.append("iscatchhandler=").append(loadBoolean("iscatchhandler", false)).append("\n");
            buf.append("\n");

            buf.append("#############Log Properties#################################\n");
            buf.append("#the buffer size of logger\n");
            buf.append("logbuffer=").append(loadInt("logbuffer", 0)).append("\n");
            buf.append("#If out put the response time in the access log\n");
            buf.append("islogresponsetime=").append(loadBoolean("islogresponsetime", true)).append("\n");
            buf.append("#If a task cost over this number in ms , then NetSign log a line in nohup.out\n");
            buf.append("longbusinesstime=").append(loadLong("longbusinesstime", 500)).append("\n");
            buf.append("#Log of nohup's config\n");
            buf.append("nohuplogconfig=").append(loadString("nohuplogconfig", "")).append("\n");
            buf.append("\n");

            buf.append("###########ISFW Properties#################################\n");
            buf.append("maxreadthread=").append(loadInt("maxreadthread", 3)).append("\n");
            buf.append("\n");

            buf.append("###########Character Properties#############################\n");
            buf.append("encoding=").append(loadString("encoding", "ISO8859-1")).append("\n");
            buf.append("\n");

            buf.append("##########ConcleLogger Properties###########################\n");
            buf.append("#is ConsoleLogger print the stacktrace of the exception\n");
            buf.append("isprintst=").append(loadBoolean("isprintst", true)).append("\n");
            buf.append("#is ConsoleLogger print debug infomation on the console\n");
            buf.append("isdebug=").append(loadBoolean("isdebug", false)).append("\n");
            buf.append("#Whether the self-check log is stored separately\n");
            buf.append("isselftest=").append(loadBoolean("isselftest", false)).append("\n");
            buf.append("#project id for debug info's print, if 0 print all\n");
            buf.append("projectid=").append(loadInt("projectid", 0)).append("\n");
            buf.append("#is ConsoleLogger save the binary content to file\n");
            buf.append("issave=").append(loadBoolean("issave", false)).append("\n");
            buf.append("\n");

            buf.append("##########JMX Moniter Properties############################\n");
            buf.append("#level of jmx moniter:none,system,full\n");
            buf.append("jmlevel=").append(loadString("jmlevel", JMX_MONITOR_LEVEL_NONE)).append("\n");
            buf.append("#max length of task queue for jmx moniter, default 2000\n");
            buf.append("tqmax=").append(loadInt("tqmax", 2000)).append("\n");
            buf.append("#interval of the watcher to wakeup the oberservers of task queue, default 60000\n");
            buf.append("tqwinterval=").append(loadLong("tqwinterval", 50)).append("\n");
            buf.append("#interval of the service infomation collector, default 60000\n");
            buf.append("sicinterval=").append(loadLong("sicinterval", 60000)).append("\n");

            buf.append("#Transaction information statistics interval, default 10000\n");
            buf.append("queryTime=").append(loadInt("queryTime", 10000)).append("\n");

            buf.append("intervalMaximum=").append(loadLong("intervalMaximum", Long.MAX_VALUE)).append("\n");
            buf.append("intervalMinimum=").append(loadLong("intervalMinimum", Long.MIN_VALUE)).append("\n");

            buf.append("#shell for count tcp connection\n");
            String num = ShellUtil.execShell("cat /opt/infosec/NetSignServer52/NetSignServer/config/extension" +
                    ".properties|grep '#tcpcc'|wc -l");
            if ("1".equals(num.trim())) {
                buf.append("#tcpcc=bin/tcpcc.sh\n");
            } else {
                buf.append("tcpcc=bin/tcpcc.sh\n");
            }
            buf.append("\n");

            buf.append("##########JCE Provider Properties############################\n");
            buf.append("verifyprovider=").append(loadString("verifyprovider", "INFOSEC")).append("\n");
            String signprovider = loadString("signprovider", "INFOSEC");
            if (signprovider.indexOf(",") > 0) {
                String[] signproviders = signProvider.split(",");
                signprovider = signproviders[0];
            }
            buf.append("signprovider=").append(signprovider).append("\n");
            buf.append("encryptprovider=").append(loadString("encryptprovider", "INFOSEC")).append("\n");
            buf.append("decryptprovider=").append(loadString("decryptprovider", "INFOSEC")).append("\n");
            buf.append("\n");

            buf.append("##########AlgMode Properties###############################\n");
            buf.append("algmode=").append(loadString("algmode", "soft")).append("\n");
            buf.append("#if store the sm2 keys into the crypto card or store keys into hsm\n");
            buf.append("usehardkeystore=").append(loadBoolean("usehardkeystore", false)).append("\n");
            buf.append("#means use SwxaJCE as provider,only when usehardkeystore=yes it works\n");
            if (loadString("hardkeystore.privatekeyalg", null) != null) {
                buf.append("hardkeystore.privatekeyalg=").append(loadString("hardkeystore.privatekeyalg", "")).append("\n");
            } else {
                buf.append("#hardkeystore.privatekeyalg=jce:SwxaJCE\n");
            }
            buf.append("#hard crypto device name( FisherManCryptoCard )\n");
            if (loadString("hardkeystore.device", null) != null) {
                buf.append("hardkeystore.device=").append(loadString("hardkeystore.device", "")).append("\n");
            } else {
                buf.append("#hardkeystore.device=FisherManCryptoCard\n");
            }
            buf.append("#A password for hard keies backup and recover\n");
            if (loadString("hardkeystore.backuppassword", null) != null) {
                buf.append("hardkeystore.backuppassword=").append(loadString("hardkeystore.backuppassword", "")).append("\n");
            } else {
                buf.append("#hardkeystore.backuppassword=11111111\n");
            }
            buf.append("\n");

            buf.append("##########PDF Properties####################################\n");
            buf.append("#Permissions of encripted pdf file:ASSEMBLY,COPY,DEGRADED_PRINTING,FILL_IN," +
                    "MODIFY_ANNOTATIONS,MODIFY_CONTENTS,PRINTING,SCREENREADERS\n");
            buf.append("#Split by ','.\n");
            String pdfP = loadString("pdfpermission", "");
            int[] pdfPermissions = new int[]{-1};
            if (!"".equals(pdfP.trim())) {
                String[] pieces = pdfP.split(",");
//				int[] pdfPermissions = new int[ 1 ];
                for (String piece : pieces) {
                    int r = getPermissionValue(piece);
                    if (r > 0) {
                        pdfPermissions[0] |= r;
                    }
                }
                if (pdfPermissions.length > 0 && pdfPermissions[0] != -1) {
                    String punct = ",";
                    buf.append("pdfpermission=");
                    for (int i = 0; i < pdfPermissions.length; i++) {
                        buf.append(parseInt2StringValue(pdfPermissions[i]));
                        if (i != (pdfPermissions.length - 1)) {
                            buf.append(punct);
                        }
                    }
                    buf.append("\n");
                }
            } else {
                buf.append("pdfpermission=").append(pdfP).append("\n");
            }
            buf.append("\n");

            buf.append("##########CRL Properties####################################\n");
            buf.append("#crl load mode , \"all\" or \"realtime\"\n");
            buf.append("crlloadmode=").append(loadString("crlloadmode", "all")).append("\n");
            buf.append("#when clean the crl catches , hour of day , split by \",\"\n");
            int[] crlct = loadCrlCleanTimes();
            for (int i = 0; i < crlct.length; i++) {
                String punct = ",";
                buf.append("crlcleantimes=").append(crlct[i]);
                if (i != crlct.length - 1) {
                    buf.append(punct);
                }
            }
            buf.append("\n");
            buf.append("#the interval to reload the crl file(ms)\n");
            buf.append("reloadcrlinterval=").append(loadLong("reloadcrlinterval", 300000)).append("\n");
            buf.append("\n");

            buf.append("##########PBC Properties####################################\n");
            buf.append("#if the bank in blacklist while it was added the first time\n");
            buf.append("inblacklist=").append(loadBoolean("inblacklist", false)).append("\n");
            buf.append("#is the bankid must match the subject dn\n");
            buf.append("ischeckbankid=").append(loadBoolean("ischeckbankid", true)).append("\n");
            buf.append("\n");

            buf.append("##########SM2 Properties####################################\n");
            buf.append("#if this system support sm2\n");
            buf.append("supportsm2=").append(loadBoolean("supportsm2", false)).append("\n");
            buf.append("#if use the hard alg\n");
            loadSM2UseHardAlg();
            if (sm2SignUseHardALG == sm2VerifyUseHardALG) {
                buf.append("usehardalg=").append(sm2SignUseHardALG).append("\n");
            } else {
                buf.append("usehardalg=").append(sm2SignUseHardALG).append(",").append(sm2VerifyUseHardALG).append(
                        "\n");
            }
            buf.append("#provider\n");
            if (loadString("algprovider", null) != null) {
                buf.append("algprovider=").append(loadString("algprovider", null)).append("\n");
            } else {
                buf.append("algprovider=\n");
            }
            buf.append("\n");

            buf.append("#encrypt use c implement algrithm\n");
            buf.append("encryptusec=").append(loadBoolean("encryptusec", false)).append("\n");
            buf.append("#the default alg while generate p10 request\n");
            buf.append("defaultsm2p10alg=").append(loadString("defaultsm2p10alg", "SM3withSM2")).append("\n");
            buf.append("#the default value of SM3 pucid. plaintext or base64 text.(111111 or base64,ABe=ABe=)\n");
            byte[] sm3pucid = loadByteArray("sm3pucid", null);
            if (sm3pucid != null) {
                buf.append("sm3pucid=").append(new String(sm3pucid)).append("\n");
            } else {
                buf.append("#sm3pucid=1234567812345678\n");
            }
            byte[] sm3signpucid = loadByteArray("sm3signpucid", null);
            if (sm3signpucid != null) {
                buf.append("sm3signpucid=").append(new String(sm3signpucid)).append("\n");
            } else {
                buf.append("#sm3signpucid=1234567812345678\n");
            }
            byte[] sm3p10puid = loadByteArray("sm3p10puid", null);
            if (sm3p10puid != null) {
                buf.append("sm3p10puid=").append(new String(loadByteArray("sm3p10puid", null))).append("\n");
            } else {
                buf.append("#sm3p10puid=1234567812345678\n");
            }
            byte[] sm3ocspucid = loadByteArray("sm3ocspucid", null);
            if (sm3ocspucid != null) {
                buf.append("sm3ocspucid=").append(new String(loadByteArray("sm3ocspucid", null))).append("\n");
            } else {
                buf.append("#sm3ocspucid=1234567812345678\n");
            }
            buf.append("#if cache the result of sm2 computation\n");
            buf.append("sm2cache=").append(loadBoolean("sm2cache", false)).append("\n");
            buf.append("sm2cachesize=").append(loadInt("sm2cachesize", 0)).append("\n");
            buf.append("#gear for control the speed sm2 sign compute.(number of return without compute/number of " +
                    "return with compute)\n");
            buf.append("sm2signgear=").append(loadString("sm2signgear", "0/1")).append("\n");
            buf.append("#gear for control the speed sm2 verify compute.(number of return without compute/number of " +
                    "return with compute)\n");
            buf.append("sm2verifygear=").append(loadString("sm2verifygear", "0/1")).append("\n");
            buf.append("envelopcache=").append(loadBoolean("envelopcache", false)).append("\n");
            buf.append("envelopcachesize=").append(loadInt("envelopcachesize", 0)).append("\n");
            buf.append("#gear for control the speed sm2 encrypt compute.(number of return without compute/number of " +
                    "return with compute)\n");
            buf.append("encryptgear=").append(loadString("encryptgear", "0/1")).append("\n");
            buf.append("#gear for control the speed sm2 decrypt compute.(number of return without compute/number of " +
                    "return with compute)\n");
            buf.append("decryptgear=").append(loadString("decryptgear", "0/1")).append("\n");
            buf.append("#If trade the SM2 signature result as an unsigned number\n");
            buf.append("integerunsigned=").append(loadBoolean("integerunsigned", true)).append("\n");
            buf.append("#if GM publickey algrithms use HSM\n");
            buf.append("gmpublicalgusehsm=").append(loadBoolean("gmpublicalgusehsm", false)).append("\n");
            buf.append("\n");

            buf.append("#The number of thread queues calling the encrypted card when using the encrypted card\n");
            buf.append("encryptcardworkingmessagequeue=").append(loadInt("encryptcardworkingmessagequeue", 1)).append("\n");
            buf.append("\n");


            buf.append("###########PKCS7 Properties#################################\n");
            buf.append("withcertchain=").append(loadBoolean("withcertchain", false)).append("\n");
            buf.append("#RSA encrytion algorithm, enveloped data type OID using Q7.\n");
            buf.append("rsaencusingq7=").append(loadBoolean("rsaencusingq7", false)).append("\n");
            buf.append("#SM2 encrytion algorithm, enveloped data type OID using Q7.\n");
            buf.append("sm2encusingq7=").append(loadBoolean("sm2encusingq7", true)).append("\n");
            buf.append("#If using Q7 as the standard while generate RSA signature.\n");
            buf.append("rsasignusingq7=").append(loadBoolean("rsasignusingq7", false)).append("\n");
            buf.append("#If using Q7 as the standard while generate SM2 signature.\n");
            buf.append("sm2signusingq7=").append(loadBoolean("sm2signusingq7", true)).append("\n");

            buf.append("#If using Q7 as the standard while generate EC signature.\n");
            buf.append("ecsinusingq7=").append(loadBoolean("ecsinusingq7", true)).append("\n");
            buf.append("#EC encrytion algorithm, enveloped data type OID using Q7.\n");
            buf.append("ecencusingq7=").append(loadBoolean("ecencusingq7", true)).append("\n");
            buf.append("#EC sign P7 algorithm, enc alg type OID using ec alg.\n");
            buf.append("ecsignuseecalgwithp7=").append(loadBoolean("ecsignuseecalgwithp7", false)).append("\n");


           /* buf.append("#using Q7 as the standard while generate EC signature.\n");
            buf.append("ecsigmustq7=").append(loadBoolean("ecsigmustq7", false)).append("\n");
            buf.append("#using Q7 as the standard while generate SM2 signature.\n");
            buf.append("sm2sigmustq7=").append(loadBoolean("sm2sigmustq7", false)).append("\n");
            buf.append("#using Q7 as the standard while generate RSA signature.\n");
            buf.append("rsasigmustq7=").append(loadBoolean("rsasigmustq7", false)).append("\n");*/

            buf.append("#If support authenticateAttributes while verify the SignedData.\n");
            buf.append("p7verifysupportauthattrs=").append(loadBoolean("p7verifysupportauthattrs", true)).append("\n");
            //p7verifyWithLength
            buf.append("#If support length while verify the SignedData.\n");
            buf.append("p7verifywithlength=").append(loadBoolean("p7verifywithlength", false)).append("\n");
            buf.append("#If cache the verify result of certs\n");
            buf.append("iscachecert=").append(loadBoolean("iscachecert", true)).append("\n");
            buf.append("#If support the verify of cert chain\n");
            buf.append("isverifycertchain=").append(loadBoolean("isverifycertchain", true)).append("\n");
            buf.append("#issupport issuerkid\n");
            buf.append("issupportissuerkid=").append(loadBoolean("issupportissuerkid", true)).append("\n");
            buf.append("\n");

            buf.append("###########RESOURCE SYNC Properties#########################\n");
            buf.append("isautoreloadresources=").append(loadBoolean("isautoreloadresources", false)).append("\n");
            buf.append("resourcereloadinterval=").append(loadLong("resourcereloadinterval", 60 * 60 * 1000)).append(
                    "\n");
            buf.append("\n");

            buf.append("###############PROCESSOR Properties#########################\n");
            buf.append("#if netsign processors auto unzip the crypto or plain text, they maybe zipped by NetSign(COM)" +
                    "\n");
            buf.append("isautounzip=").append(loadBoolean("isautounzip", false)).append("\n");
            buf.append("#if the verify processors returns the certificate infomations and plain, only for performance" +
                    " tests\n");
            buf.append("isreturnverifyresult=").append(loadBoolean("isreturnverifyresult", true)).append("\n");
            buf.append("#if the signing processors returns the crypto text, only for performance tests\n");
            buf.append("isreturnsignresult=").append(loadBoolean("isreturnsignresult", true)).append("\n");
            buf.append("#if the importing or gening symmkey processors need check key and alg match, or importing " +
                    "asymmkey processor need check keypair\n");
            buf.append("ischeckmatch=").append(loadBoolean("ischeckmatch", false)).append("\n");
            buf.append("\n");

            buf.append("##########Unstandard Signature Properties##################\n");
            buf.append("#Double hash signature for KunLun bank , if sign on outer \"Files\" node in xml\n");
            buf.append("klbsignouterfields=").append(loadBoolean("klbsignouterfields", true)).append("\n");
            buf.append("\n");

            buf.append("#############Week Algorithm Properties#####################\n");
            buf.append("#If check the week algorithms.\n");
            buf.append("checkweekalg=").append(loadBoolean("checkweekalg", true)).append("\n");
            buf.append("\n");

            buf.append("#############Auto GC Interval#####################\n");
            buf.append("autogcinterval=").append(loadInt("autogcinterval", 0)).append("\n");
            buf.append("\n");

            buf.append("#Generate a real-scene certificate key pair. 1/n of all key pairs\n");
            int gear = loadInt("genkeypairgear", 1);
            buf.append("genkeypairgear=").append(Math.max(gear, 1)).append("\n");
            buf.append("\n");

            buf.append("#start keypair lazy load\n");
            buf.append("lazy.load.asymm.key=").append(loadBoolean("lazy.load.asymm.key", lazyLoadAsymmKey)).append(
                    "\n");
            buf.append("\n");

            buf.append("############Keypair Pool Properties#######################\n");
            buf.append("sm2.pool.size=").append(loadInt("sm2.pool.size", sm2PoolSize)).append("\n");
            buf.append("rsa1024.pool.size=").append(loadInt("rsa1024.pool.size", rsa1024PoolSize)).append("\n");
            buf.append("rsa2048.pool.size=").append(loadInt("rsa2048.pool.size", rsa2048PoolSize)).append("\n");
            buf.append("\n");

            buf.append("#Symmetric encryption and decryption\n");
            buf.append("symm.provider=").append(loadString("symm.provider", symmProvider)).append("\n");
            buf.append("\n");

            buf.append("#Whether the network connection platform generates a random key every time it encrypts\n");
            buf.append("wangliangenrandomkey=").append(loadBoolean("wangliangenrandomkey", false)).append("\n");
            buf.append("\n");

            buf.append("#Whether to force gc\n");
            buf.append("forcegc=").append(loadBoolean("forcegc", forceGC)).append("\n");
            buf.append("\n");

            buf.append("#Another triggering condition for forcing GC, the proportion of aging generation\n");
            buf.append("oldgenusedratio=").append(loadInt("oldgenusedratio", oldGenUsedRatio)).append("\n");
            buf.append("\n");

            buf.append("#Whether to Delete RAWCert\n");
            buf.append("isDeleteRAWCert=").append(loadBoolean("isDeleteRAWCert", isDeleteRAWCert)).append("\n");
            buf.append("\n");

            buf.append("#Whether to check the legitimacy of the public key before verifying the national secret " +
                    "signatur\n");
            buf.append("ischecksm2pubk=").append(loadBoolean("ischecksm2pubk", isCheckSM2Pubk)).append("\n");
            buf.append("\n");

            buf.append("#Whether to send notice\n");
            buf.append("issendnotice=").append(loadBoolean("issendnotice", false)).append("\n");
            buf.append("\n");

            buf.append("#When uploading the certificate, the bankid starting with this character is not checked\n");
            StringBuilder banKids = new StringBuilder();
            for (int i = 0; i < nocheckBankid.length; i++) {
                String punct = ",";
                banKids.append(nocheckBankid[i]);
                if (i != nocheckBankid.length - 1) {
                    banKids.append(punct);
                }
            }
            buf.append("nocheckbankid=").append(loadString("nocheckbankid", banKids.toString())).append("\n");
            buf.append("\n");

            buf.append("#Whether the certificate file is stored separately\n");
            buf.append("extract.cert.file=").append(loadBoolean("extract.cert.file", extractCertFile)).append("\n");
            buf.append("\n");

            buf.append("#Whether the keypair list index uses CN DN, it is enabled by default. After opening, it may " +
                    "cause index conflicts at your own risk\n");
            buf.append("use.dn.and.cn.index=").append(loadBoolean("use.dn.and.cn.index", useCnAndDnIndex)).append("\n");
            buf.append("\n");

            buf.append("#Thread pool custom threads\n");
            buf.append("thread.count.4.keypair.pool=").append(loadInt("thread.count.4.keypair.pool",
                    threadCount4KeyPairPool)).append("\n");
            buf.append("\n");

            buf.append("#Open the encryption card synchronization lock\n");
            buf.append("lock4cryptocard=").append(loadBoolean("lock4cryptocard", lock4CryptoCard)).append("\n");
            buf.append("\n");

            buf.append("#Industrial Bank encrypted library path\n");
            buf.append("lib.industrial.bank.crypto.path=").append(loadString("lib.industrial.bank.crypto.path",
                    libIndustrialBankCryptoPath)).append("\n");
            buf.append("\n");

            buf.append("#############WCS Extend Properties#####################\n");
            buf.append("genrsa1024poolsize=").append(loadInt("genrsa1024poolsize", 0)).append("\n");
            buf.append("genrsa1024threadcount=").append(loadInt("genrsa1024threadcount", 0)).append("\n");
            buf.append("genrsa2048poolsize=").append(loadInt("genrsa2048poolsize", 0)).append("\n");
            buf.append("genrsa2048threadcount=").append(loadInt("genrsa2048threadcount", 0)).append("\n");
            buf.append("wcsencpassword=").append(loadString("wcsencpassword", "123456")).append("\n");
            buf.append("\n");

            buf.append("#Supports the configuration of whether the serial number carries 0 when the serial number of " +
                    "the identity ID is used\n");
            buf.append("#The default is false (serial number without 0)\n");
            buf.append("cert.sn.with0=").append(loadBoolean("cert.sn.with0", false)).append("\n");
            buf.append("\n");

            buf.append("#chose new version or old version serialVersionUID when syncing\n");
            buf.append("isnewserialversionuid=").append(loadBoolean("isnewserialversionuid", true)).append("\n");
            buf.append("\n");

            buf.append("#Certificate group configuration items\n");
            buf.append("enc.cert.for.sign=").append(loadBoolean("enc.cert.for.sign", false)).append("\n");
            buf.append("\n");
            //
            buf.append("#Whether the empty node when RSA P10 is generated is reserved. true reserved, false not " +
                    "reserved\n");
            buf.append("p10.rsa.null=").append(loadBoolean("p10.rsa.null", true)).append("\n");
            buf.append("\n");

            buf.append("#Whether the empty node when SM2 P10 is generated is reserved. true reserved, false not " +
                    "reserved\n");
            buf.append("p10.sm2.null=").append(loadBoolean("p10.sm2.null", true)).append("\n");

            buf.append("#Whether to synchronize the search key for asymmetric encryption (default is false, not " +
                    "synchronized)\n");
            buf.append("asymm.encrypt.syn=").append(loadBoolean("asymm.encrypt.syn", false)).append("\n");

            buf.append("#Whether to obtain the certificate synchronously for asymmetric decryption (default is false," +
                    " not synchronous)\n");
            buf.append("asymm.decrypt.syn=").append(loadBoolean("asymm.decrypt.syn", false)).append("\n");

            buf.append("#Whether decryption supports organization number (default is true, support organization " +
                    "number)\n");
            buf.append("asymm.decrypt.support.bank.code=").append(loadBoolean("asymm.decrypt.support.bank.code",
                    true)).append("\n");


            buf.append("#Whether to enable SDF mode\n");
            buf.append("mode.sdf=").append(loadBoolean("mode.sdf", true)).append("\n");
            buf.append("\n");

            buf.append("#Ministry of Finance: Whether to verify the certificate when unpacking the digital envelope, " +
                    "the default is false)\n");
            buf.append("decrypt.enveloped.check.cert=").append(loadBoolean("decrypt.enveloped.check.cert", false)).append("\n");

            buf.append("#When P7 is generated, with or without NULL node\n");
            buf.append("p7.discard.null=").append(loadBoolean("p7.discard.null", false)).append("\n");
            buf.append("\n");

            buf.append("#Requirement for Bank of Communications 9152: Can I find the certificate closest to the system time based on the certificate subject\n");
            buf.append("query.loader=").append(loadString("query.loader", "default")).append("\n");
            buf.append("\n");

            //syn.batch
            buf.append("#Batch synchronization, turn off synchronization on startup\n");
            buf.append("start.syn.batch=").append(loadBoolean("start.syn.batch", false)).append("\n");
            buf.append("\n");
            buf.append("#PBE alg param, CSSP HTTP export KEK and import KEK\n");
            buf.append("pbe.SKF.alg=").append(loadString("pbe.SKF.alg", "PBEWithSHA256And256BitAES-CBC-BC")).append("\n");
            buf.append("pbe.salt=").append(loadString("pbe.salt", "PBESalt")).append("\n");
            buf.append("pbe.iteration=").append(loadInt("pbe.iteration", 10)).append("\n");
            buf.append("pbe.digest.alg=").append(loadString("pbe.digest.alg", "SHA1")).append("\n");
            buf.append("pbe.SFK.alg=").append(loadString("pbe.SFK.alg", "PBEWITHSHAAND128BITRC4")).append("\n");
            buf.append("pbe.provider=").append(loadString("pbe.provider", "INFOSEC")).append("\n");
            buf.append("pbe.symm.alg=").append(loadString("pbe.symm.alg", "AES/CBC/PKCS7Padding")).append("\n");
            buf.append("pbe.symm.IV=").append(loadString("pbe.symm.IV", "1234567812345678")).append("\n");
            buf.append("\n");
            buf.append("#Batch synchronization, turn off synchronization on startup\n");
            buf.append("p10.cfca.p9Attribute=").append(loadBoolean("p10.cfca.p9Attribute", false)).append("\n");
            buf.append("\n");
            buf.append("check.oscca.standards=").append(loadBoolean("check.oscca.standards", false)).append("\n");
            buf.append("\n");
            buf.append("check.sm2.oscca.standards=").append(loadBoolean("check.sm2.oscca.standards", true)).append("\n");
            buf.append("\n");

            //external.key.operation.crypto.card"
            buf.append("#Whether to use external keys for card operations\n");
            buf.append("external.key.operation.crypto.card=").append(loadBoolean("external.key.operation.crypto.card", true)).append("\n");
            buf.append("\n");


            //useCwithSM3
            buf.append("#Using C for SM3 operations\n");
            buf.append("useCwithSM3=").append(loadBoolean("useCwithSM3", false)).append("\n");
            //syn.scheduled.service.timeout
            buf.append("#The default timeout for synchronous associated server timed detection is considered unavailable for associated server tasks beyond this time. Exiting this task with this parameter is to prevent setting the timeout time to be too long, resulting in an infinite increase in queue size. If the timeout time is set to exceed 15 seconds, the task device will be offline.\n");
            buf.append("syn.scheduled.service.timeout=").append(loadLong("syn.scheduled.service.timeout", 15000)).append("\n");

            buf.append("#gen random use card\n");
            buf.append("genrandomusecard=").append(loadBoolean("genrandomusecard", false)).append("\n");
            buf.append("# cavium use soft when cavium unavailable:data format or card error").append("\n");
//            caviumUseSoftWhenFailed = caviumUseSoftWhenFailed == null ? "false" : caviumUseSoftWhenFailed;
            buf.append("cavium.use.soft.when.unavailable=").append(loadBoolean("cavium.use.soft.when.unavailable", false)).append("\n");
            buf.append("#Regenerate the ciphertext when the first byte of the public key information X in the ciphertext is 0 when it is used as an SM2 service\n");
            buf.append("regenerateCryptoTextForSM2=").append(loadBoolean("regenerateCryptoTextForSM2", false)).append("\n");
            buf.append("\n");
            buf.append("#Whether to record evidence in the access log before the service is processed\n");
            buf.append("isrecordingstarttime=").append(loadBoolean("isrecordingstarttime", false)).append("\n");
            buf.append("\n");
            buf.append("#Whether the symmetric algorithm OID in the digital envelope uses a non-standard OID\n");
            buf.append("envelopSM4OIDUseUnStandard=").append(loadBoolean("envelopsm4oiduseunstandard", false)).append("\n");
            buf.append("\n");

            ConfigUtil.save(filepath, buf.toString().getBytes("GBK"), 3);
        } catch (Exception e) {
            ConsoleLogger.logException(e);
        } finally {
            FileUtil.closeIO(reader, null);
        }

    }

    /**
     * 拼接字符串，生成extension.properties
     *
     * @param filepath
     */
    public synchronized static void save(String filepath) {
        try {
            StringBuilder buf = new StringBuilder();
            buf.append("##########IO Properties##################################\n");
            buf.append("backlog=").append(backLog).append("\n");
            buf.append("#if open the session monitor thread to close the idle connections\n");
            buf.append("issessionmonitoropen=").append(isSessionMonitorOpen).append("\n");
            buf.append("#max sessions the monitor carries\n");
            buf.append("maxsessionpoolsize=").append(maxSessionPoolSize).append("\n");
            buf.append("\n");

            buf.append("##########Thread Pool Properties##########################\n");
            buf.append("#count of core thread of the threadpool\n");
            buf.append("threadpoolcore=").append(threadPoolCore).append("\n");
            buf.append("#max count of thread of the threadpool\n");
            buf.append("threadpoolmax=").append(threadPoolMax).append("\n");
            buf.append("threadpoolqueue=").append(threadPoolQueue).append("\n");
            buf.append("#if catch the handler for close them\n");
            buf.append("iscatchhandler=").append(isCatchHandler).append("\n");
            buf.append("\n");

            buf.append("#############Log Properties#################################\n");
            buf.append("#the buffer size of logger\n");
            buf.append("logbuffer=").append(logBuffer).append("\n");
            buf.append("#If out put the response time in the access log\n");
            buf.append("islogresponsetime=").append(isLogRespTime).append("\n");
            buf.append("#If a task cost over this number in ms , then NetSign log a line in nohup.out\n");
            buf.append("longbusinesstime=").append(longBusinessTime).append("\n");
            buf.append("#Log of nohup's config\n");
            buf.append("nohuplogconfig=").append(nohupLogConfig == null ? "" : nohupLogConfig).append("\n");
            buf.append("\n");

            buf.append("###########ISFW Properties#################################\n");
            buf.append("maxreadthread=").append(maxReadThread).append("\n");
            buf.append("\n");

            buf.append("###########Character Properties#############################\n");
            if (encoding != null) {
                buf.append("encoding=").append(encoding).append("\n");
            } else {
                buf.append("encoding=").append("\n");
            }
            buf.append("\n");

            buf.append("##########ConcleLogger Properties###########################\n");
            buf.append("#is ConsoleLogger print the stacktrace of the exception\n");
            buf.append("isprintst=").append(isPrintST).append("\n");
            buf.append("#is ConsoleLogger print debug infomation on the console\n");
            buf.append("isdebug=").append(isDebug).append("\n");
            buf.append("#Whether the self-check log is stored separately\n");
            buf.append("isselftest=").append(selfTest).append("\n");
            buf.append("#project id for debug info's print, if 0 print all\n");
            buf.append("projectid=").append(projectID).append("\n");
            buf.append("#is ConsoleLogger save the binary content to file\n");
            buf.append("issave=").append(isSave).append("\n");
            buf.append("\n");

            buf.append("##########JMX Moniter Properties############################\n");
            buf.append("#level of jmx moniter:none,system,full\n");
            buf.append("jmlevel=").append(jmxMonitorLevel).append("\n");
            buf.append("#max length of task queue for jmx moniter, default 2000\n");
            buf.append("tqmax=").append(taskQueueMax).append("\n");
            buf.append("#interval of the watcher to wakeup the oberservers of task queue, default 60000\n");
            buf.append("tqwinterval=").append(taskQueueWatchInterval).append("\n");

            buf.append("#Transaction information statistics interval, default 10000\n");
            buf.append("queryTime=").append(queryTime).append("\n");

            buf.append("intervalMaximum=").append(intervalMaximum).append("\n");
            buf.append("intervalMinimum=").append(intervalMinimum).append("\n");


            buf.append("#interval of the service infomation collector, default 60000\n");
            buf.append("sicinterval=").append(serviceInfoCollectInterval).append("\n");
            buf.append("#shell for count tcp connection\n");
            String num = ShellUtil.execShell("cat /opt/infosec/NetSignServer52/NetSignServer/config/extension" +
                    ".properties|grep '#tcpcc'|wc -l");
            if ("1".equals(num.trim())) {
                buf.append("#tcpcc=bin/tcpcc.sh\n");
            } else {
                buf.append("tcpcc=bin/tcpcc.sh\n");
            }
            buf.append("\n");

            buf.append("##########JCE Provider Properties############################\n");
            buf.append("verifyprovider=").append(verifyProvider).append("\n");
            buf.append("signprovider=").append(signProvider).append("\n");
            buf.append("encryptprovider=").append(encryptProvider).append("\n");
            buf.append("decryptprovider=").append(decryptProvider).append("\n");
            buf.append("\n");

            buf.append("##########AlgMode Properties###############################\n");
            buf.append("algmode=").append(algMode).append("\n");
            buf.append("#if store the sm2 keys into the crypto card or store keys into hsm\n");
            buf.append("usehardkeystore=").append(useHardKeyStore).append("\n");
            buf.append("#means use SwxaJCE as provider,only when usehardkeystore=yes it works\n");
            if (privateKeyAlg != null) {
                buf.append("hardkeystore.privatekeyalg=").append(privateKeyAlg).append("\n");
            } else {
                buf.append("#hardkeystore.privatekeyalg=jce:SwxaJCE\n");
            }
            buf.append("#hard crypto device name( FisherManCryptoCard )\n");
            if (hardKeyStoreDevice != null && !("".equals(hardKeyStoreDevice))) {
                buf.append("hardkeystore.device=").append(hardKeyStoreDevice).append("\n");
            } else {
                buf.append("#hardkeystore.device=FisherManCryptoCard\n");
            }
            buf.append("#A password for hard keies backup and recover\n");
            if (hardKeyStroreBackupPassword != null && !("".equals(hardKeyStroreBackupPassword))) {
                buf.append("hardkeystore.backuppassword=").append(hardKeyStroreBackupPassword).append("\n");
            } else {
                buf.append("#hardkeystore.backuppassword=11111111\n");
            }
            buf.append("\n");

            buf.append("##########PDF Properties####################################\n");
            buf.append("#Permissions of encripted pdf file:ASSEMBLY,COPY,DEGRADED_PRINTING,FILL_IN," +
                    "MODIFY_ANNOTATIONS,MODIFY_CONTENTS,PRINTING,SCREENREADERS\n");
            buf.append("#Split by ','.\n");
            if (pdfPermissions.length > 0 && pdfPermissions[0] != -1) {
                String punct = ",";
                int[] intpers = pdfPermissions;
                buf.append("pdfpermission=");
                for (int i = 0; i < intpers.length; i++) {
                    buf.append(parseInt2StringValue(intpers[i]));
                    if (i != (intpers.length - 1)) {
                        buf.append(punct);
                    }
                }
                buf.append("\n");
            } else {
                buf.append("pdfpermission=\n");
            }
            buf.append("\n");

            buf.append("##########CRL Properties####################################\n");
            buf.append("#crl load mode , \"all\" or \"realtime\"\n");
            if (crlLoadMode != null) {
                buf.append("crlloadmode=").append(crlLoadMode).append("\n");
            } else {
                buf.append("crlloadmode=").append("\n");
            }
            buf.append("#when clean the crl catches , hour of day , split by \",\"\n");
            int[] crlct = crlCleanTimes;
            for (int i = 0; i < crlct.length; i++) {
                String punct = ",";
                buf.append("crlcleantimes=").append(crlct[i]);
                if (i != crlct.length - 1) {
                    buf.append(punct);
                }
            }
            buf.append("\n");
            buf.append("#the interval to reload the crl file(ms)\n");
            buf.append("reloadcrlinterval=").append(reloadCRLInterval).append("\n");
            buf.append("\n");

            buf.append("##########PBC Properties####################################\n");
            buf.append("#if the bank in blacklist while it was added the first time\n");
            buf.append("inblacklist=").append(inBlackList).append("\n");
            buf.append("#is the bankid must match the subject dn\n");
            buf.append("ischeckbankid=").append(isCheckBankID).append("\n");
            buf.append("\n");

            buf.append("##########SM2 Properties####################################\n");
            buf.append("#if this system support sm2\n");
            buf.append("supportsm2=").append(supportsm2).append("\n");
            buf.append("#if use the hard alg\n");
            if (sm2SignUseHardALG == sm2VerifyUseHardALG) {
                buf.append("usehardalg=").append(sm2SignUseHardALG).append("\n");
            } else {
                buf.append("usehardalg=").append(sm2SignUseHardALG).append(",").append(sm2VerifyUseHardALG).append(
                        "\n");
            }
            buf.append("#provider\n");
            if (sm2Provider != null) {
                buf.append("algprovider=").append(sm2Provider).append("\n");
            } else {
                buf.append("algprovider=").append("\n");
            }
            buf.append("\n");

            buf.append("#encrypt use c implement algrithm\n");
            buf.append("encryptusec=").append(isUsingCImp).append("\n");
            buf.append("#the default alg while generate p10 request\n");
            buf.append("defaultsm2p10alg=").append(defaultSM2P10Alg).append("\n");
            buf.append("#the default value of SM3 pucid. plaintext or base64 text.(111111 or base64,ABe=ABe=)\n");
            if (SM3CertpucID != null) {
                buf.append("sm3pucid=").append(new String(SM3CertpucID)).append("\n");
            } else {
                buf.append("sm3pucid=\n");
            }
            if (SM3SignpucID != null) {
                buf.append("sm3signpucid=").append(new String(SM3SignpucID)).append("\n");
            } else {
                buf.append("sm3signpucid=\n");
            }
            if (SM3P10PucID != null) {
                buf.append("sm3p10puid=").append(new String(SM3P10PucID)).append("\n");
            } else {
                buf.append("sm3p10puid=\n");
            }
            if (SM3OCSPPucID != null) {
                buf.append("sm3ocspucid=").append(new String(SM3OCSPPucID)).append("\n");
            } else {
                buf.append("sm3ocspucid=\n");
            }
            //SM3OCSPPucID
            buf.append("#if cache the result of sm2 computation\n");
            buf.append("sm2cache=").append(sm2Cache).append("\n");
            buf.append("sm2cachesize=").append(sm2CacheSize).append("\n");
            buf.append("#gear for control the speed sm2 sign compute.(number of return without compute/number of " +
                    "return with compute)\n");
            buf.append("sm2signgear=").append(sm2SignGear).append("\n");
            buf.append("#gear for control the speed sm2 verify compute.(number of return without compute/number of " +
                    "return with compute)\n");
            buf.append("sm2verifygear=").append(sm2VerifyGear).append("\n");
            buf.append("envelopcache=").append(envelopCache).append("\n");
            buf.append("envelopcachesize=").append(envelopCacheSize).append("\n");
            buf.append("#gear for control the speed sm2 encrypt compute.(number of return without compute/number of " +
                    "return with compute)\n");
            if (encryptGear != null) {
                buf.append("encryptgear=").append(encryptGear).append("\n");
            } else {
                buf.append("encryptgear=").append("\n");
            }
            buf.append("#gear for control the speed sm2 decrypt compute.(number of return without compute/number of " +
                    "return with compute)\n");
            if (decryptGear != null) {
                buf.append("decryptgear=").append(decryptGear).append("\n");
            } else {
                buf.append("decryptgear=").append("\n");
            }
            buf.append("#If trade the SM2 signature result as an unsigned number\n");
            buf.append("integerunsigned=").append(integerUnsigned).append("\n");
            buf.append("#if GM publickey algrithms use HSM\n");
            buf.append("gmpublicalgusehsm=").append(GMPublicAlgUseHSM).append("\n");
            buf.append("\n");

            buf.append("#The number of thread queues calling the encrypted card when using the encrypted card\n");
            buf.append("encryptcardworkingmessagequeue=").append(encryptCardWorkingMessageQueue).append("\n");
            buf.append("\n");

            buf.append("###########PKCS7 Properties#################################\n");
            buf.append("withcertchain=").append(withCertChain).append("\n");
            buf.append("#RSA encrytion algorithm, enveloped data type OID using Q7.\n");
            buf.append("rsaencusingq7=").append(rsaEncUsingQ7).append("\n");
            buf.append("#SM2 encrytion algorithm, enveloped data type OID using Q7.\n");
            buf.append("sm2encusingq7=").append(sm2EncUsingQ7).append("\n");
            buf.append("#If using Q7 as the standard while generate RSA signature.\n");
            buf.append("rsasignusingq7=").append(rsaSignUsingQ7).append("\n");
            buf.append("#If using Q7 as the standard while generate SM2 signature.\n");
            buf.append("sm2signusingq7=").append(sm2SignUsingQ7).append("\n");
            buf.append("#If using Q7 as the standard while generate EC signature.\n");
            buf.append("ecsinusingq7=").append(ecSigUsingQ7).append("\n");
            buf.append("#EC encrytion algorithm, enveloped data type OID using Q7.\n");
            buf.append("ecencusingq7=").append(ecEncUsingQ7).append("\n");
            buf.append("#EC sign P7 algorithm, enc alg type OID using ec alg.\n");
            buf.append("ecsignuseecalgwithp7=").append(ECSignUseECAlgWithP7).append("\n");

          /*  buf.append("#using Q7 as the standard while generate EC signature.\n");
            buf.append("ecsigmustq7=").append(ECSigMustQ7).append("\n");
            buf.append("#using Q7 as the standard while generate SM2 signature.\n");
            buf.append("sm2sigmustq7=").append(SM2SigMustQ7).append("\n");
            buf.append("#using Q7 as the standard while generate RSA signature.\n");
            buf.append("rsasigmustq7=").append(RSASigMustQ7).append("\n");*/

            buf.append("#If support authenticateAttributes while verify the SignedData.\n");
            buf.append("p7verifysupportauthattrs=").append(p7VerifySupportAuthAttrs).append("\n");

            buf.append("#If support length while verify the SignedData.\n");
            buf.append("p7verifywithlength=").append(p7verifyWithLength).append("\n");
            buf.append("#If cache the verify result of certs\n");
            buf.append("iscachecert=").append(isCacheCert).append("\n");
            buf.append("#If support the verify of cert chain\n");
            buf.append("isverifycertchain=").append(isVerifyCertChain).append("\n");
            buf.append("#issupport issuerkid\n");
            buf.append("issupportissuerkid=").append(isSupportIssuerKid).append("\n");
            buf.append("\n");

            buf.append("###########RESOURCE SYNC Properties#########################\n");
            buf.append("isautoreloadresources=").append(isAutoReloadResources).append("\n");
            buf.append("resourcereloadinterval=").append(resourceReloadInterval).append("\n");
            buf.append("\n");

            buf.append("###############PROCESSOR Properties#########################\n");
            buf.append("#if netsign processors auto unzip the crypto or plain text, they maybe zipped by NetSign(COM)" +
                    "\n");
            buf.append("isautounzip=").append(isAutoUnzip).append("\n");
            buf.append("#if the verify processors returns the certificate infomations and plain, only for performance" +
                    " tests\n");
            buf.append("isreturnverifyresult=").append(isReturnVerifyResult).append("\n");
            buf.append("#if the signing processors returns the crypto text, only for performance tests\n");
            buf.append("isreturnsignresult=").append(isReturnSignResult).append("\n");
            buf.append("#if the importing or gening symmkey processors need check key and alg match, or importing " +
                    "asymmkey processor need check keypair\n");
            buf.append("ischeckmatch=").append(isCheckMatch).append("\n");
            buf.append("\n");

            buf.append("##########Unstandard Signature Properties##################\n");
            buf.append("#Double hash signature for KunLun bank , if sign on outer \"Files\" node in xml\n");
            buf.append("klbsignouterfields=").append(KLBSignOuterFields).append("\n");
            buf.append("\n");

            buf.append("#############Week Algorithm Properties#####################\n");
            buf.append("#If check the week algorithms.\n");
            buf.append("checkweekalg=").append(checkWeekAlg).append("\n");
            buf.append("\n");

            buf.append("#############firebird DB#################################\n");
            buf.append("isCollectData=").append(isCollectData).append("\n");
            buf.append("\n");

            buf.append("#############Auto GC Interval#####################\n");
            buf.append("autogcinterval=").append(autoGCInterval).append("\n");
            buf.append("\n");

            buf.append("#Generate a real-scene certificate key pair. 1/n of all key pairs\n");
            buf.append("genkeypairgear=").append(genKeyPairGear).append("\n");
            buf.append("\n");

            buf.append("#start keypair lazy load\n");
            buf.append("lazy.load.asymm.key=").append(lazyLoadAsymmKey).append("\n");
            buf.append("\n");

            buf.append("############Keypair Pool Properties#######################\n");
            buf.append("sm2.pool.size=").append(sm2PoolSize).append("\n");
            buf.append("rsa1024.pool.size=").append(rsa1024PoolSize).append("\n");
            buf.append("rsa2048.pool.size=").append(rsa2048PoolSize).append("\n");
            buf.append("\n");

            buf.append("#Symmetric encryption and decryption\n");
            buf.append("symm.provider=").append(symmProvider).append("\n");
            buf.append("\n");

            buf.append("#Whether the network connection platform generates a random key every time it encrypts\n");
            buf.append("wangliangenrandomkey=").append(wanglianGenRandomKey).append("\n");
            buf.append("\n");

            buf.append("#Whether to force gc\n");
            buf.append("forcegc=").append(forceGC).append("\n");
            buf.append("\n");

            buf.append("#Another triggering condition for forcing GC, the proportion of aging generation\n");
            buf.append("oldgenusedratio=").append(oldGenUsedRatio).append("\n");
            buf.append("\n");

            buf.append("#Whether to Delete RAWCert\n");
            buf.append("isDeleteRAWCert=").append(isDeleteRAWCert).append("\n");
            buf.append("\n");

            buf.append("#Whether to check the legitimacy of the public key before verifying the national secret " +
                    "signatur\n");
            buf.append("ischecksm2pubk=").append(isCheckSM2Pubk).append("\n");
            buf.append("\n");

            buf.append("#Whether to send notice\n");
            buf.append("issendnotice=").append(isSendNotice).append("\n");
            buf.append("\n");

            buf.append("#When uploading the certificate, the bankid starting with this character is not checked\n");
            StringBuilder banKids = new StringBuilder();
            for (int i = 0; i < nocheckBankid.length; i++) {
                String punct = ",";
                banKids.append(nocheckBankid[i]);
                if (i != nocheckBankid.length - 1) {
                    banKids.append(punct);
                }
            }
            buf.append("nocheckbankid=").append(banKids.toString()).append("\n");
            buf.append("\n");

            buf.append("#Whether the certificate file is stored separately\n");
            buf.append("extract.cert.file=").append(extractCertFile).append("\n");
            buf.append("\n");

            buf.append("#Whether the keypair list index uses CN DN, it is enabled by default. After opening, it may " +
                    "cause index conflicts at your own risk\n");
            buf.append("use.dn.and.cn.index=").append(useCnAndDnIndex).append("\n");
            buf.append("\n");

            buf.append("#Thread pool custom threads\n");
            buf.append("thread.count.4.keypair.pool=").append(threadCount4KeyPairPool).append("\n");
            buf.append("\n");

            buf.append("#Open the encryption card synchronization lock\n");
            buf.append("lock4cryptocard=").append(lock4CryptoCard).append("\n");
            buf.append("\n");

            buf.append("#Industrial Bank encrypted library path\n");
            if (libIndustrialBankCryptoPath != null) {
                buf.append("lib.industrial.bank.crypto.path=").append(libIndustrialBankCryptoPath).append("\n");
            } else {
                buf.append("lib.industrial.bank.crypto.path=").append("\n");
            }
            buf.append("\n");

            buf.append("#############WCS Extend Properties#####################\n");
            buf.append("genrsa1024poolsize=").append(genRSA1024PoolSize).append("\n");
            buf.append("genrsa1024threadcount=").append(genRSA1024ThreadCount).append("\n");
            buf.append("genrsa2048poolsize=").append(genRSA2048PoolSize).append("\n");
            buf.append("genrsa2048threadcount=").append(genRSA2048ThreadCount).append("\n");
            buf.append("wcsencpassword=").append(wechartstockEncpassword).append("\n");
            buf.append("\n");

            buf.append("#Supports the configuration of whether the serial number carries 0 when the serial number of " +
                    "the identity ID is used\n");
            buf.append("#The default is false (serial number without 0)\n");
            buf.append("cert.sn.with0=").append(snWith0).append("\n");

            buf.append("#chose new version or old version serialVersionUID when syncing\n");
            buf.append("isnewserialversionuid=").append(isNewSerialVersionUID).append("\n");
            buf.append("\n");

            buf.append("#Certificate group configuration items\n");
            buf.append("enc.cert.for.sign=").append(encCertForSign).append("\n");
            buf.append("\n");

            buf.append("#Whether the empty node when RSA P10 is generated is reserved. true reserved, false not " +
                    "reserved\n");
            buf.append("p10.rsa.null=").append(p10RsaWithNull).append("\n");
            buf.append("\n");

            buf.append("#Whether the empty node when SM2 P10 is generated is reserved. true reserved, false not " +
                    "reserved\n");
            buf.append("p10.sm2.null=").append(p10Sm2WithNull).append("\n");

            buf.append("#Whether to synchronize the search key for asymmetric encryption (default is false, not " +
                    "synchronized)\n");
            buf.append("asymm.encrypt.syn=").append(asymmEncryptSyn).append("\n");

            buf.append("#Whether to obtain the certificate synchronously for asymmetric decryption (default is false," +
                    " not synchronous)\n");
            buf.append("asymm.decrypt.syn=").append(asymmDecryptSyn).append("\n");

            buf.append("#Whether decryption supports organization number (default is true, support organization " +
                    "number)\n");
            buf.append("asymm.decrypt.support.bank.code = ").append(decryptSupportBankCode).append("\n");

            buf.append("#Ministry of Finance: Whether to verify the certificate when unpacking the digital envelope, " +
                    "the default is false)\n");
            buf.append("decrypt.enveloped.check.cert=").append(decryptEnvelopeCheckCert).append("\n");


            buf.append("#Whether to enable SDF mode\n");
            buf.append("mode.sdf=").append(sdfMode).append("\n");
            buf.append("\n");

            buf.append("#When P7 is generated, with or without NULL node\n");
            buf.append("p7.discard.null=").append(p7WithNull).append("\n");
            buf.append("\n");

            buf.append("#Requirement for Bank of Communications 9152: Can I find the certificate closest to the system time based on the certificate subject\n");
            buf.append("query.loader=").append(queryLoader).append("\n");
            buf.append("subject.query=").append(subjectQuery).append("\n");
            buf.append("\n");
            buf.append("#PBE alg param, CSSP HTTP export KEK and import KEK\n");
            buf.append("pbe.SKF.alg=").append(loadString("pbe.SKF.alg", "PBEWithSHA256And256BitAES-CBC-BC")).append("\n");
            buf.append("pbe.salt=").append(loadString("pbe.salt", "PBESalt")).append("\n");
            buf.append("pbe.iteration=").append(loadInt("pbe.iteration", 10)).append("\n");
            buf.append("pbe.digest.alg=").append(loadString("pbe.digest.alg", "SHA1")).append("\n");
            buf.append("pbe.SFK.alg=").append(loadString("pbe.SFK.alg", "PBEWITHSHAAND128BITRC4")).append("\n");
            buf.append("pbe.provider=").append(loadString("pbe.provider", "INFOSEC")).append("\n");
            buf.append("pbe.symm.alg=").append(loadString("pbe.symm.alg", "AES/CBC/PKCS7Padding")).append("\n");
            buf.append("pbe.symm.IV=").append(loadString("pbe.symm.IV", "1234567812345678")).append("\n");
            buf.append("\n");
            //syn.batch
            buf.append("#Batch synchronization, turn off synchronization on startup\n");
            buf.append("start.syn.batch=").append(synBatch).append("\n");
            buf.append("\n");
            buf.append("p10.cfca.p9Attribute=").append(p10CFCAWithAttibute).append("\n");
            buf.append("\n");
            buf.append("check.oscca.standards=").append(checkOSCCAStandards4PBC2G).append("\n");
            buf.append("\n");
            buf.append("check.sm2.oscca.standards=").append(checkSM2OSCCAStandards4PBC2G).append("\n");
            buf.append("\n");
            buf.append("#Whether to use external keys for card operations\n");
            buf.append("external.key.operation.crypto.card=").append(isExtKeyUseCard).append("\n");
            buf.append("\n");
            buf.append("#Using C for SM3 operations\n");
            buf.append("useCwithSM3=").append(isUsingCSM3).append("\n");
            buf.append("\n");
            buf.append("#The default timeout for synchronous associated server timed detection is considered unavailable for associated server tasks beyond this time. Exiting this task with this parameter is to prevent setting the timeout time to be too long, resulting in an infinite increase in queue size. If the timeout time is set to exceed 15 seconds, the task device will be offline.\n");
            buf.append("syn.scheduled.service.timeout=").append(synScheduledServiceTimeOut).append("\n");
            buf.append("\n");
            buf.append("#gen random use card\n");
            buf.append("genrandomusecard=").append(genRandomUseCard).append("\n");
            //regenerateCryptoTextForSM2
            buf.append("\n");
            buf.append("#Regenerate the ciphertext when the first byte of the public key information X in the ciphertext is 0 when it is used as an SM2 service\n");
            buf.append("regenerateCryptoTextForSM2=").append(regenerateCryptoTextForSM2).append("\n");
            buf.append("\n");
            buf.append("# cavium use soft when cavium unavailable:data format or card error").append("\n");
//            caviumUseSoftWhenFailed = caviumUseSoftWhenFailed == null ? "false" : caviumUseSoftWhenFailed;
            buf.append("cavium.use.soft.when.unavailable = ").append(caviumUseSoftWhenFailed).append("\n");
            buf.append("\n");
            buf.append("#Whether to record evidence in the access log before the service is processed\n");
            buf.append("isrecordingstarttime=").append(isRecordingStartTime).append("\n");
            buf.append("\n");
            buf.append("#Whether the symmetric algorithm OID in the digital envelope uses a non-standard OID\n");
            buf.append("envelopsm4oiduseunstandard=").append(envelopSM4OIDUseUnStandard).append("\n");
            buf.append("\n");

            ConfigUtil.save(filepath, buf.toString().getBytes("GBK"), 3);
        } catch (Exception e) {
            ConsoleLogger.logException(e);
        }
    }

    /**
     * 修改内存
     *
     * @param configName
     * @param configValue
     */
    public synchronized static boolean set2Mem(String configName, String configValue) {
        String filepath = ConfigManager.getConfigFile(ConfigManager.getConfigPath(), "extension.properties");
        try {
            FileInputStream inStream = new FileInputStream(filepath);
            prop.load(inStream);
            ConsoleLogger.logString("configValue", configValue);
            /*if(DataUtils.isEmpty(configValue)){
                configValue="";
            }*/
            prop.setProperty(configName, configValue);
//			prop.list( System.out );
            //System.out.println("Modify:" + configName + "=" + configValue);

            if ("isdebug".equals(configName)) {
                isDebug = loadBoolean("isdebug", false);
                ConsoleLogger.isDebug = isDebug;
                CryptoUtil.debug = isDebug;
                // 2020-06-11 为isfj中的日志debug赋值
                cn.com.infosec.util.ConsoleLogger.isDebug = isDebug;
                cn.com.infosec.netsign.der.util.ConsoleLogger.isDebug = isDebug;
            }
            if ("isselftest".equals(configName)) {
                selfTest = loadBoolean("isselftest", false);
            }

            if ("isprintst".equals(configName)) {
                isPrintST = loadBoolean("isprintst", true);
            }

            if ("issave".equals(configName)) {
                isSave = loadBoolean("issave", false);
                ConsoleLogger.isSave = isSave;
            }

            if ("nohuplogconfig".equals(configName)) {
                nohupLogConfig = loadString("nohuplogconfig", null);
            }

            if ("threadpoolcore".equals(configName)) {
                threadPoolCore = loadInt("threadpoolcore", 50);
            }

            if ("threadpoolmax".equals(configName)) {
                threadPoolMax = loadInt("threadpoolmax", 500);
            }

            if ("threadpoolqueue".equals(configName)) {
                threadPoolQueue = loadInt("threadpoolqueue", 30000);
            }

            if ("iscatchhandler".equals(configName)) {
                isCatchHandler = loadBoolean("iscatchhandler", false);
            }

            if ("logbuffer".equals(configName)) {
                logBuffer = loadInt("logbuffer", 0);
            }

            if ("syslogsystem".equals(configName)) {
                syslogSystem = loadString("syslogsystem", syslogSystem);
            }

            if ("syslogaccess".equals(configName)) {
                syslogAccess = loadString("syslogaccess", syslogAccess);
            }

            if ("syslogdebug".equals(configName)) {
                syslogDebug = loadString("syslogdebug", syslogDebug);
            }

            if ("checkvalidity".equals(configName)) {
                isCheckCertValidity = loadBoolean("checkvalidity", true);
            }

            if ("encoding".equals(configName)) {
                encoding = loadString("encoding", "ISO8859-1");
            }

            if ("jmlevel".equals(configName)) {
                jmxMonitorLevel = loadString("jmlevel", JMX_MONITOR_LEVEL_NONE);
            }

            if ("tqmax".equals(configName)) {
                taskQueueMax = loadInt("tqmax", 2000);
            }

            if ("tqwinterval".equals(configName)) {
                taskQueueWatchInterval = loadLong("tqwinterval", 50);
            }

            if ("sicinterval".equals(configName)) {
                serviceInfoCollectInterval = loadLong("sicinterval", 60000);
            }

            if ("projectid".equals(configName)) {
                projectID = loadInt("projectid", 0);
            }

            if ("maxreadthread".equals(configName)) {
                maxReadThread = loadInt("maxreadthread", 3);
            }

            if ("algmode".equals(configName)) {
                algMode = loadString("algmode", "soft");
            }

            if ("verifyprovider".equals(configName)) {
                verifyProvider = loadString("verifyprovider", "INFOSEC");
                if (verifyProvider.indexOf(",") > 0) {
                    verifyProviders = verifyProvider.split(",");
                    verifyProvider = verifyProviders[0];
                }
            }

            if ("signprovider".equals(configName)) {
                signProvider = loadString("signprovider", "INFOSEC");
                if (signProvider.indexOf(",") > 0) {
                    signProviders = signProvider.split(",");
                    signProvider = signProviders[0];
                }
            }

            if ("encryptprovider".equals(configName)) {
                encryptProvider = loadString("encryptprovider", "INFOSEC");
            }

            if ("decryptprovider".equals(configName)) {
                decryptProvider = loadString("decryptprovider", "INFOSEC");
            }

            if ("backlog".equals(configName)) {
                backLog = loadInt("backlog", 200);
            }

            // ---2013-12-05 LH.
            if ("subFilter".equals(configName)) {
                subFilter = loadString("subFilter", "adbe.pkcs7.detached");
            }

            if ("signnotation".equals(configName)) {
                signNotation = loadString("signnotation", signNotation);
            }

            if ("stampfile".equals(configName)) {
                stampFile = loadString("stampfile", stampFile);
            }

            if ("pdfpermission".equals(configName)) {
                String pdfP = loadString("pdfpermission", "");
                if (!"".equals(pdfP.trim())) {
                    String[] pieces = pdfP.split(",");
                    pdfPermissions = new int[1];
                    for (String piece : pieces) {
                        int r = getPermissionValue(piece);
                        if (r > 0) {
                            pdfPermissions[0] |= r;
                        }
                    }
                }
            }

            if ("inblacklist".equals(configName)) {
                inBlackList = loadBoolean("inblacklist", false);
            }

            if ("crlcleantimes".equals(configName)) {
                crlCleanTimes = loadCrlCleanTimes();
            }

            if ("reloadcrlinterval".equals(configName)) {
                reloadCRLInterval = loadLong("reloadcrlinterval", 300000);
            }

            if ("crlloadmode".equals(configName)) {
                crlLoadMode = loadString("crlloadmode", "all");
            }

            if ("supportsm2".equals(configName)) {
                supportsm2 = loadBoolean("supportsm2", false);
            }

            if ("usehardkeystore".equals(configName)) {
                useHardKeyStore = loadBoolean("usehardkeystore", false);
                sm2UseHardKeyStore = useHardKeyStore;
            }

            if ("hardkeystore.privatekeyalg".equals(configName)) {
                privateKeyAlg = loadString("hardkeystore.privatekeyalg", null);
            }

            if ("usehardalg".equals(configName)) {
                loadSM2UseHardAlg();
            }

            if ("algprovider".equals(configName)) {
                sm2Provider = loadString("algprovider", null);
                sm2Provider = "".equals(sm2Provider) ? null : sm2Provider;
            }

            if ("defaultsm2p10alg".equals(configName)) {
                defaultSM2P10Alg = loadString("defaultsm2p10alg", "SM3withSM2");
            }

            if ("sm3pucid".equals(configName)) {
                SM3CertpucID = loadByteArray("sm3pucid", null);
            }

            if ("sm3signpucid".equals(configName)) {
                SM3SignpucID = loadByteArray("sm3signpucid", null);
            }

            if ("sm3p10puid".equals(configName)) {
                SM3P10PucID = loadByteArray("sm3p10puid", null);
            }

            if ("sm3ocspucid".equals(configName)) {
                SM3OCSPPucID = loadByteArray("sm3ocspucid", null);
            }

            if ("sm2cache".equals(configName)) {
                sm2Cache = loadBoolean("sm2cache", false);
            }

            if ("sm2cachesize".equals(configName)) {
                sm2CacheSize = loadInt("sm2cachesize", 0);
            }

            if ("sm2signgear".equals(configName)) {
                sm2SignGear = loadString("sm2signgear", "0/1");
            }

            if ("sm2verifygear".equals(configName)) {
                sm2VerifyGear = loadString("sm2verifygear", "0/1");
            }

            if ("envelopcache".equals(configName)) {
                envelopCache = loadBoolean("envelopcache", false);
            }

            if ("envelopcachesize".equals(configName)) {
                envelopCacheSize = loadInt("envelopcachesize", 0);
            }

            if ("encryptgear".equals(configName)) {
                encryptGear = loadString("encryptgear", "0/1");
            }

            if ("decryptgear".equals(configName)) {
                decryptGear = loadString("decryptgear", "0/1");
            }

            if ("withcertchain".equals(configName)) {
                withCertChain = loadBoolean("withcertchain", false);
            }

            if ("isautoreloadresources".equals(configName)) {
                isAutoReloadResources = loadBoolean("isautoreloadresources", false);
            }

            if ("isCollectData".equals(configName)) {
                isCollectData = loadBoolean("isCollectData", false);
            }

            if ("resourcereloadinterval".equals(configName)) {
                resourceReloadInterval = loadLong("resourcereloadinterval", 60 * 60 * 1000);
            }

            if ("isautounzip".equals(configName)) {
                isAutoUnzip = loadBoolean("isautounzip", false);
            }

            if ("isreturnverifyresult".equals(configName)) {
                isReturnVerifyResult = loadBoolean("isreturnverifyresult", true);
            }

            if ("isreturnsignresult".equals(configName)) {
                isReturnSignResult = loadBoolean("isreturnsignresult", true);
            }

            if ("issessionmonitoropen".equals(configName)) {
                isSessionMonitorOpen = loadBoolean("issessionmonitoropen", false);
            }

            if ("maxsessionpoolsize".equals(configName)) {
                maxSessionPoolSize = loadInt("maxsessionpoolsize", 10240);
            }

            if ("p7verifysupportauthattrs".equals(configName)) {
                p7VerifySupportAuthAttrs = loadBoolean("p7verifysupportauthattrs", true);
            }

            if ("p7verifywithlength".equals(configName)) {
                p7verifyWithLength = loadBoolean("p7verifywithlength", false);
            }
            if ("rsasignusingq7".equals(configName)) {
                rsaSignUsingQ7 = loadBoolean("rsasignusingq7", false);
            }

            if ("sm2signusingq7".equals(configName)) {
                sm2SignUsingQ7 = loadBoolean("sm2signusingq7", true);
            }

            if ("rsaencusingq7".equals(configName)) {
                rsaEncUsingQ7 = loadBoolean("rsaencusingq7", false);
            }

            if ("sm2encusingq7".equals(configName)) {
                sm2EncUsingQ7 = loadBoolean("sm2encusingq7", true);
            }

            if ("encryptusec".equals(configName)) {
                isUsingCImp = loadBoolean("encryptusec", false);
            }

            if ("integerunsigned".equals(configName)) {
                integerUnsigned = loadBoolean("integerunsigned", true);
            }

            if ("gmpublicalgusehsm".equals(configName)) {
                GMPublicAlgUseHSM = loadBoolean("gmpublicalgusehsm", false);
            }
            if ("encryptcardworkingmessagequeue".equals(configName)) {
                encryptCardWorkingMessageQueue = loadInt("encryptcardworkingmessagequeue", 1);
            }


            if ("islogresponsetime".equals(configName)) {
                isLogRespTime = loadBoolean("islogresponsetime", true);
            }

            if ("longbusinesstime".equals(configName)) {
                longBusinessTime = loadLong("longbusinesstime", 500);
            }

            if ("ischeckbankid".equals(configName)) {
                isCheckBankID = loadBoolean("ischeckbankid", true);
            }

            if ("klbsignouterfields".equals(configName)) {
                KLBSignOuterFields = loadBoolean("klbsignouterfields", true);
            }

            if ("hardkeystore.device".equals(configName)) {
                hardKeyStoreDevice = loadString("hardkeystore.device", null);
            }

            if ("hardkeystore.backuppassword".equals(configName)) {
                hardKeyStroreBackupPassword = loadString("hardkeystore.backuppassword", null);
            }

            if ("checkweekalg".equals(configName)) {
                checkWeekAlg = loadBoolean("checkweekalg", true);
            }

            if ("iscachecert".equals(configName)) {
                isCacheCert = loadBoolean("iscachecert", true);
            }

            if ("isverifycertchain".equals(configName)) {
                isVerifyCertChain = loadBoolean("isverifycertchain", true);
            }

            if ("issupportissuerkid".equals(configName)) {
                isSupportIssuerKid = loadBoolean("issupportissuerkid", true);
            }

            if ("isissuerdncasematch".equals(configName)) {
                isIssuerDNCaseMatch = loadBoolean("isissuerdncasematch", true);
            }

            if ("sm2sigmustq7".equals(configName)) {
                SM2SigMustQ7 = loadBoolean("sm2sigmustq7", false);
            }

            if ("rsasigmustq7".equals(configName)) {
                RSASigMustQ7 = loadBoolean("rsasigmustq7", false);
            }
            if ("ecencusingq7".equals(configName)) {
                ecEncUsingQ7 = loadBoolean("ecencusingq7", false);
            }

            if ("ecsignuseecalgwithp7".equals(configName)) {
                ECSignUseECAlgWithP7 = loadBoolean("ecsignuseecalgwithp7", false);
            }
            if ("ecsinusingq7".equals(configName)) {
                ecSigUsingQ7 = loadBoolean("ecsinusingq7", false);
            }
            if ("sm2sigmustseq".equals(configName)) {
                SM2SigMustSeq = loadBoolean("sm2sigmustseq", false);
            }

            if ("sm2sigmustunsignedint".equals(configName)) {
                SM2SigMustUnsignedInt = loadBoolean("sm2sigmustunsignedint", false);
            }

            if ("sm2sigmustsignedint".equals(configName)) {
                SM2SigMustSignedInt = loadBoolean("sm2sigmustsignedint", false);
            }

            if ("needcheckosccastandards".equals(configName)) {
                needCheckOSCCAStandards = loadBoolean("needcheckosccastandards", false);
            }

            /*
             * @since 5.5.40.5
             */
            if (NetSignImpl.PROVIDER_SWXA_ALG.equals(ExtendedConfigOld.getPrivateKeyAlg())
                    && ExtendedConfigOld.isUsehardkeystore() && (ExtendedConfigOld.getHardKeyStoreDevice() == null)) {
                signProvider = NetSignImpl.PROVIDER_SWXA;
            }

            /*
             * @since 5.5.40.5
             */
            if (NetSignImpl.PROVIDER_SWXA_ALG.equals(ExtendedConfigOld.getPrivateKeyAlg())
                    && (ExtendedConfigOld.isUsehardkeystore()) && (ExtendedConfigOld.getHardKeyStoreDevice() == null)) {
                decryptProvider = NetSignImpl.PROVIDER_SWXA;
            }

            if ("autogcinterval".equals(configName)) {
                autoGCInterval = loadInt("autogcinterval", 0);
            }

            if ("genkeypairgear".equals(configName)) {
                genKeyPairGear = loadInt("genkeypairgear", 1);
                genKeyPairGear = Math.max(genKeyPairGear, 1);
            }

            if ("lazy.load.asymm.key".equals(configName)) {
                lazyLoadAsymmKey = loadBoolean("lazy.load.asymm.key", true);
            }
            if ("sm2.pool.size".equals(configName)) {
                sm2PoolSize = loadInt("sm2.pool.size", 0);
            }
            if ("rsa1024.pool.size".equals(configName)) {
                rsa1024PoolSize = loadInt("rsa1024.pool.size", 0);
            }
            if ("rsa2048.pool.size".equals(configName)) {
                rsa2048PoolSize = loadInt("rsa2048.pool.size", 0);
            }

            if ("queryTime".equals(configName)) {
                queryTime = loadInt("queryTime", 10000);
            }
            if ("intervalMaximum".equals(configName)) {
                intervalMaximum = loadLong("intervalMaximum", Long.MAX_VALUE);
            }
            if ("intervalMinimum".equals(configName)) {
                intervalMinimum = loadLong("intervalMinimum", Long.MIN_VALUE);
            }
            if ("symm.provider".equals(configName)) {
                symmProvider = loadString("symm.provider", "INFOSEC");
            }
            if ("wanglianGenRandomKey".equals(configName)) {
                wanglianGenRandomKey = loadBoolean("wanglianGenRandomKey", false);
            }

            if ("forcegc".equals(configName)) {
                forceGC = loadBoolean("forcegc", false);
            }

            if ("oldgenusedratio".equals(configName)) {
                oldGenUsedRatio = loadInt("oldgenusedratio", 0);
            }
            if ("isDeleteRAWCert".equals(configName)) {
                isDeleteRAWCert = loadBoolean("isDeleteRAWCert", true);
            }
            if ("issendnotice".equals(configName)) {
                isSendNotice = loadBoolean("issendnotice", false);
            }
            if ("ischecksm2pubk".equals(configName)) {
                isCheckSM2Pubk = loadBoolean("ischecksm2pubk", true);
            }
            if ("nocheckbankid".equals(configName)) {
                String bankidstr = loadString("nocheckbankid", "");
                if (!"".equals(bankidstr.trim())) {
                    String[] bankids = bankidstr.split(",");
                    if (bankids.length >= 0) {
                        nocheckBankid = new String[bankids.length];
                        System.arraycopy(bankids, 0, nocheckBankid, 0, bankids.length);
                    }
                } else {
                    nocheckBankid = new String[0];
                }
            }

            if ("envelopeSignerIDUseKid".equals(configName)) {
                envelopeSignerIDUseKid = loadBoolean("envelopeSignerIDUseKid", true);
            }
            if ("extract.cert.file".equals(configName)) {
                extractCertFile = loadBoolean("extract.cert.file", true);
            }
            if ("use.dn.and.cn.index".equals(configName)) {
                useCnAndDnIndex = loadBoolean("use.dn.and.cn.index", true);
            }
            if ("thread.count.4.keypair.pool".equals(configName)) {
                threadCount4KeyPairPool = loadInt("thread.count.4.keypair.pool", 0);
            }
            if ("lock4cryptocard".equals(configName)) {
                lock4CryptoCard = loadBoolean("lock4cryptocard", true);
            }

            if ("lib.industrial.bank.crypto.path".equals(configName)) {
                libIndustrialBankCryptoPath = loadString("lib.industrial.bank.crypto.path", "");
            }

            if ("cert.sn.with0".equals(configName)) {
                snWith0 = loadBoolean("cert.sn.with0", false);
            }
            if ("ischeckmatch".equals(configName)) {
                isCheckMatch = loadBoolean("ischeckmatch", false);
            }

            if ("isnewserialversionuid".equals(configName)) {
                isNewSerialVersionUID = loadBoolean("isnewserialversionuid", true);
            }

            if ("enc.cert.for.sign".equals(configName)) {
                encCertForSign = loadBoolean("enc.cert.for.sign", false);
            }
            if ("p10.rsa.null".equals(configName)) {
                p10RsaWithNull = loadBoolean("p10.rsa.null", true);
            }
            if ("p10.sm2.null".equals(configName)) {
                p10Sm2WithNull = loadBoolean("p10.sm2.null", true);
            }

            if ("asymm.encrypt.syn".equals(configName)) {
                asymmEncryptSyn = loadBoolean("asymm.encrypt.syn", false);
            }
            if ("asymm.decrypt.syn".equals(configName)) {
                asymmDecryptSyn = loadBoolean("asymm.decrypt.syn", false);
            }
            if ("asymm.decrypt.support.bank.code".equals(configName)) {
                decryptSupportBankCode = loadBoolean("asymm.decrypt.support.bank.code", true);
            }

            if ("decrypt.enveloped.check.cert".equals(configName)) {
                decryptEnvelopeCheckCert = loadBoolean("decrypt.enveloped.check.cert", false);
            }

            if ("mode.sdf".equals(configName)) {
                sdfMode = loadBoolean("mode.sdf", false);
            }
            if ("p7.discard.null".equals(configName)) {
                p7WithNull = loadBoolean("p7.discard.null", false);
            }
            if ("pbe.SKF.alg".equals(configName)) {
                pbeSKFAlg = loadString("pbe.SKF.alg", "PBEWithSHA256And256BitAES-CBC-BC");
            }
            if ("pbe.salt".equals(configName)) {
                pbeSalt = loadString("pbe.salt", "PBESalt");
            }
            if ("pbe.iteration".equals(configName)) {
                pbeIteration = loadInt("pbe.iteration", 10);
            }
            if ("pbe.provider".equals(configName)) {
                pbeProvider = loadString("pbe.provider", "INFOSEC");
            }
            if ("pbe.symm.alg".equals(configName)) {
                pbeSymmAlg = loadString("pbe.symm.alg", "AES/CBC/PKCS7Padding");
            }
            if ("pbe.symm.IV".equals(configName)) {
                pbeSymmIV = loadString("pbe.symm.IV", "1234567812345678");
            }
            if ("query.loader".equals(configName)) {
                queryLoader = loadString("query.loader", "default");
            }
            if ("subject.query".equals(configName)) {
                subjectQuery = loadBoolean("subject.query", false);
            }
            if ("subject.query".equals(configName)) {
                subjectQuery = loadBoolean("subject.query", false);
            }
            if ("p10.cfca.p9Attribute".equals(configName)) {
                p10CFCAWithAttibute = loadBoolean("p10.cfca.p9Attribute", false);
            }
            //check.oscca.standards
            if ("check.oscca.standards".equals(configName)) {
                checkOSCCAStandards4PBC2G = loadBoolean("check.oscca.standards", false);
            }
            if ("check.sm2.oscca.standards".equals(configName)) {
                checkSM2OSCCAStandards4PBC2G = loadBoolean("check.sm2.oscca.standards", true);
            }
            if ("external.key.operation.crypto.card".equals(configName)) {
                isExtKeyUseCard = loadBoolean("external.key.operation.crypto.card", true);
            }
            if ("useCwithSM3".equals(configName)) {
                isUsingCSM3 = loadBoolean("useCwithSM3", false);
            }
            //syn.scheduled.service.timeout
            if ("syn.scheduled.service.timeout".equals(configName)) {
                synScheduledServiceTimeOut = loadLong("syn.scheduled.service.timeout", 15000);
            }
            if ("genrandomusecard".equals(configName)) {
                genRandomUseCard = loadBoolean("genrandomusecard", false);
            }
            // add since 2024.02.22 农信银增加cavium验签失败时候使用软验签 useSoftWhenCaviumUnavailable
            if ("cavium.use.soft.when.unavailable".equals(configName)) {
                caviumUseSoftWhenFailed = loadBoolean("cavium.use.soft.when.unavailable", false);
                add2CaviumSystemProperty(String.valueOf(caviumUseSoftWhenFailed));
            }
            if("regenerateCryptoTextForSM2".equals(configName)){
                regenerateCryptoTextForSM2 = loadBoolean("regenerateCryptoTextForSM2", false);
            }
            //isRecordingStartTime
            if ("isrecordingstarttime".equals(configName)) {
                isRecordingStartTime = loadBoolean("isrecordingstarttime", false);
            }
            //p7SymmOIDUseUnStandard
            if("envelopsm4oiduseunstandard".equals(configName)){
                envelopSM4OIDUseUnStandard = loadBoolean("envelopSM4OIDUseUnStandard", false);
            }
            //syn.batch=
            inStream.close();
        } catch (Exception e) {
            ConsoleLogger.logException(e);
            return false;
        }
        return true;

    }

    private static String parseInt2StringValue(int value) {
        String result = null;
        if (value == PDF_ALLOW_ASSEMBLY) {
            result = "ASSEMBLY";
        } else if (value == PDF_ALLOW_COPY) {
            result = "COPY";
        } else if (value == PDF_ALLOW_DEGRADED_PRINTING) {
            result = "DEGRADED_PRINTING";
        } else if (value == PDF_ALLOW_FILL_IN) {
            result = "FILL_IN";
        } else if (value == PDF_ALLOW_MODIFY_ANNOTATIONS) {
            result = "MODIFY_ANNOTATIONS";
        } else if (value == PDF_ALLOW_MODIFY_CONTENTS) {
            result = "MODIFY_CONTENTS";
        } else if (value == PDF_ALLOW_PRINTING) {
            result = "PRINTING";
        } else if (value == PDF_ALLOW_SCREENREADERS) {
            result = "SCREENREADERS";
        }
        return result;
    }


    public static SerialVersionConfig getVersionConfig() {
        return versionConfig;
    }

    private static long loadSynResultUID(Properties prop) {
        try {
            String str = prop.getProperty("SYNResultUID").trim();
            return Long.parseLong(str);
        } catch (Exception e) {
            return -2568838557748795022L;
        }
    }

    private static long loadSynParametersUID(Properties prop) {
        try {
            String str = prop.getProperty("SYNParametersUID").trim();
            return Long.parseLong(str);
        } catch (Exception e) {
            return -6229289390556895506L;
        }
    }

    private static long loadSynEmissaryUID(Properties prop) {
        try {
            String str = prop.getProperty("SynEmissaryUID").trim();
            return Long.parseLong(str);
        } catch (Exception e) {
            return 6947734347308319163L;
        }
    }

    private static long loadRawCertSynEmissaryUID(Properties prop) {
        try {
            String str = prop.getProperty("RAWCertSynEmissaryUID").trim();
            return Long.parseLong(str);
        } catch (Exception e) {
            return -7889621339778225484L;
        }
    }

    public static boolean isEnableHealthCheck() {
        return enableHealthCheck;
    }

    public static void setEnableHealthCheck(boolean enableHealthCheck) {
        ExtendedConfigOld.enableHealthCheck = enableHealthCheck;
    }

    public static int getCheckInterval() {
        return checkInterval;
    }

    public static void setCheckInterval(int checkInterval) {
        ExtendedConfigOld.checkInterval = checkInterval;
    }

    public static int getConnTimeout() {
        return connTimeout;
    }

    public static void setConnTimeout(int connTimeout) {
        ExtendedConfigOld.connTimeout = connTimeout;
    }

    public static int getReadTimeout() {
        return readTimeout;
    }

    public static void setReadTimeout(int readTimeout) {
        ExtendedConfigOld.readTimeout = readTimeout;
    }

    public static int getRetryCount() {
        return retryCount;
    }

    public static void setRetryCount(int retryCount) {
        ExtendedConfigOld.retryCount = retryCount;
    }

    public static boolean isEcEncUsingQ7() {
        return ecEncUsingQ7;
    }

    public static void setEcEncUsingQ7(boolean ecEncUsingQ7) {
        ExtendedConfigOld.ecEncUsingQ7 = ecEncUsingQ7;
    }

    public static void setCrlCleanTimes(int[] crlCleanTimes) {
        ExtendedConfigOld.crlCleanTimes = crlCleanTimes;
    }

    public static void setReloadCRLInterval(long reloadCRLInterval) {
        ExtendedConfigOld.reloadCRLInterval = reloadCRLInterval;
    }

    public static String getCrlLoadMode() {
        return crlLoadMode;
    }

    public static void setCrlLoadMode(String crlLoadMode) {
        ExtendedConfigOld.crlLoadMode = crlLoadMode;
    }

    public static boolean isSynBatch() {
        return synBatch;
    }

    public static void setSynBatch(boolean synBatch) {
        ExtendedConfigOld.synBatch = synBatch;
    }

    private static void add2CaviumSystemProperty(String property) {
        // property
        System.setProperty("useSoftWhenCaviumUnavailable", property);
    }

    public static boolean isRecordingStartTime() {
        return isRecordingStartTime;
    }

    public static String getSystemMode() {
        return systemMode;
    }

    public static void setSystemMode(String systemMode) {
        ExtendedConfigOld.systemMode = systemMode;
    }
}
