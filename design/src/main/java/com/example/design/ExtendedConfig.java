package com.example.design;

import cn.com.infosec.netsign.base.processors.util.ShellUtil;
import cn.com.infosec.netsign.basic.system.ServerConfig;
import cn.com.infosec.netsign.basic.system.SystemInfoConsts;
import cn.com.infosec.netsign.common.annotation.DefaultValue;
import cn.com.infosec.netsign.common.constant.CommonConstants;
import cn.com.infosec.netsign.common.system.AlgorithmConsts;
import cn.com.infosec.netsign.common.util.DataUtils;
import cn.com.infosec.netsign.common.util.ProReflectUtils;
import cn.com.infosec.netsign.config.BasicConfigManager;
import cn.com.infosec.netsign.config.BasicExtensionConfig;
import cn.com.infosec.netsign.config.BasicLogConfig;
import cn.com.infosec.netsign.config.SerialVersionConfig;
import cn.com.infosec.netsign.crypto.util.Base64;
import cn.com.infosec.netsign.crypto.util.CryptoUtil;
import cn.com.infosec.netsign.frame.util.ConfigUtil;
import cn.com.infosec.netsign.logger.ConsoleLogger;

import java.io.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * @author don't know who create it, but hoary modify it
 */
public class ExtendedConfig {
    private static Map<String, String> key2FieldMap;

    private static final String SEP_COMMA = ",";

    /**
     * jmx监控等级：不监控
     */
    public static final String JMX_MONITOR_LEVEL_NONE = "none";
    /**
     * jmx监控等级：只监控系统信息
     */
    public static final String JMX_MONITOR_LEVEL_SYSTEM = "system";
    /**
     * jmx监控等级：监控所有信息
     */
    public static final String JMX_MONITOR_LEVEL_FULL = "full";

    private static Set<String> jmxLevelSet;

    public static final int PDF_ALLOW_ASSEMBLY = 1024;

    public static final int PDF_ALLOW_COPY = 16;

    public static final int PDF_ALLOW_DEGRADED_PRINTING = 4;

    public static final int PDF_ALLOW_FILL_IN = 256;

    public static final int PDF_ALLOW_MODIFY_ANNOTATIONS = 32;

    public static final int PDF_ALLOW_MODIFY_CONTENTS = 8;

    public static final int PDF_ALLOW_PRINTING = 2052;

    public static final int PDF_ALLOW_SCREENREADERS = 512;


    public static final String SHELL_FILE_NAME_CPUSTATUS = "cpustat";

    public static final String SHELL_FILE_NAME_MAXMEMORY = "maxmem";

    public static final String SHELL_FILE_NAME_FREEMEMORY = "freemem";

    public static final String SHELL_FILE_NAME_MAXHARDDISK = "maxhd";

    public static final String SHELL_FILE_NAME_FREEHARDDISK = "freehd";

    public static final String SHELL_FILE_NAME_TCPTRANSSTAT = "tcptrans";

    public static final String SHELL_FILE_NAME_TCPCONNCOUNT = "tcpcc";

    // 5.5.40.14
    private static boolean USE_TCP_CONNCOUNT;

    private static boolean sm2UseHardKeyStore;

    /**
     * below
     * @since 5.5.40.12 patch6
     */
    private static short signProviderWheel;

    private static short verifyProviderWheel;

    private static boolean envelopeSignerIDUseKid = true;

    private static boolean signAndEnvelopedEncSign;

    private static boolean signAndEnvelopedDecSign;

    /**
     *服务远程日志协议
     */
    private static String syslogProtocol;
    /**
     *服务远程日志协议是SSL时配置文件位置
     */
    private static String syslogProtocolSSLConfigPath;

    private static boolean sm2SignUseHardALG = true;

    private static boolean sm2VerifyUseHardALG = true;

    private static SerialVersionConfig versionConfig;

    private static final String newNewSerialVersionFile = SystemInfoConsts.configPath +
            "/newSerialVersionUID.properties";
    private static final String oldNewSerialVersionFile = SystemInfoConsts.configPath +
            "/oldSerialVersionUID.properties";

    private static Properties prop;

    private static String[] verifyProviders;
    private static String[] signProviders;
    /**
     * 上传证书时，以该字符开头的bankid，不做检查
     *
     * @since 5.5.40.12 patch17
     */
    private static String[] nocheckBankid = new String[0];

    private static int[] pdfPermissions = new int[]{-1};

    private static int[] crlCleanTimes;


    private static byte[] sm3CertPuid;

    private static byte[] sm3P10Puid;

    private static byte[] sm3SignPuid;

    private static byte[] sm3OCSPPuid;

    private static Object signProviderLock = new Object();

    private static Object verifyProviderLock = new Object();


    @DefaultValue(key = "backlog", type = CommonConstants.TI, intValue = 200,
            title = "##########IO Properties##################################")
    private static int backLog;

    /**
     * soeck session monitor配置，用于主动关闭闲置的socket连接
     */
    @DefaultValue(key = "issessionmonitoropen", type = CommonConstants.TB,
            comment = "#if open the session monitor thread to close the idle connections")
    private static boolean isSessionMonitorOpen;

    @DefaultValue(key = "maxsessionpoolsize", type = CommonConstants.TI, intValue = 10240,
            comment = "#max sessions the monitor carries")
    private static int maxSessionPoolSize;

    @DefaultValue(key = "threadpoolcore", type = CommonConstants.TI, intValue = 50,
            title = "##########Thread Pool Properties##########################",
            comment = "#count of core thread of the threadpool")
    private static int threadPoolCore;

    @DefaultValue(key = "threadpoolmax", type = CommonConstants.TI, intValue = 500,
            comment = "#max count of thread of the threadpool")
    private static int threadPoolMax;

    @DefaultValue(key = "threadpoolqueue", type = CommonConstants.TI, intValue = 30000)
    private static int threadPoolQueue;

    /**
     * 是否在线程池执行任务时是否缓存线程，如果不进行缓存在长连接时修改配置后需要等超时
     */
    @DefaultValue(key = "iscatchhandler", type = CommonConstants.TB,
            comment = "#if catch the handler for close them")
    private static boolean isCatchHandler;

    /**
     * 单位为k
     */
    @DefaultValue(key = "logbuffer", type = CommonConstants.TI,
            title = "#############Log Properties#################################",
            comment = "#the buffer size of logger, kb")
    private static int logBuffer;

    @DefaultValue(key = "islogresponsetime", type = CommonConstants.TB, boolValue = true,
            comment = "#If out put the response time in the access log")
    private static boolean isLogRespTime;

    @DefaultValue(key = "longbusinesstime", type = CommonConstants.TL, longValue = 500,
            comment = "#If a task cost over this number in ms , then NetSign log a line in nohup.out")
    private static long longBusinessTime;

    @DefaultValue(key = "nohuplogconfig", comment = "#Log of nohup's config")
    private static String nohupLogConfig;


    @DefaultValue(key = "maxreadthread", type = CommonConstants.TI, intValue = 3,
            title = "###########ISFW Properties#################################")
    private static int maxReadThread;

    @DefaultValue(key = "encoding", value = "ISO8859-1",
            title = "###########Character Properties#############################")
    private static String encoding;

    @DefaultValue(key = "isprintst", type = CommonConstants.TB, boolValue = true,
            title = "##########ConcleLogger Properties###########################",
            comment = "#is ConsoleLogger print the stacktrace of the exception")
    private static boolean isPrintST;

    @DefaultValue(key = "isdebug", type = CommonConstants.TB,
            comment = "#is ConsoleLogger print debug infomation on the console")
    private static boolean isDebug;

    /**
     *是否开启自检日志单独存储
     */
    @DefaultValue(key = "isselftest", type = CommonConstants.TB,
            comment = "#Whether the self-check log is stored separately")
    private static boolean selfTest;

    @DefaultValue(key = "projectid", type = CommonConstants.TI,
            comment = "#project id for debug info's print, if 0 print all")
    private static int projectID;

    @DefaultValue(key = "issave", type = CommonConstants.TB,
            comment = "#is ConsoleLogger save the binary content to file")
    private static boolean isSave;


    /**
     * jmx监控等级: none/system/full
     */
    @DefaultValue(key = "jmlevel", value = JMX_MONITOR_LEVEL_NONE,
            title = "##########JMX Moniter Properties############################",
            comment = "#level of jmx moniter:none,system,full")
    private static String jmxMonitorLevel;

    /**
     * 最大监控项目队列
     */
    @DefaultValue(key = "tqmax", type = CommonConstants.TI, intValue = 2000,
            comment = "#max length of task queue for jmx moniter, default 2000")
    private static int taskQueueMax;

    /**
     * 查询监控项目队列的时间间隔
     */
    @DefaultValue(key = "tqwinterval", type = CommonConstants.TI, intValue = 50,
            comment = "#interval of the watcher to wakeup the oberservers of task queue")
    private static long taskQueueWatchInterval;

    @DefaultValue(key = "sicinterval", type = CommonConstants.TL, longValue = 60000,
            comment = "#interval of the service infomation collector, default 60000")
    private static long serviceInfoCollectInterval;

    /**
     * 2020/02/19 查询统计间隔时间
     */
    @DefaultValue(key = "queryTime", type = CommonConstants.TI, intValue = 10000,
            comment = "#Transaction information statistics interval, default 10000")
    private static long queryTime;
    /**
     * 后台处理为微秒
     */
    @DefaultValue(key = "intervalMaximum", type = CommonConstants.TL, longValue = Long.MAX_VALUE)
    private static long intervalMaximum;

    @DefaultValue(key = "intervalMinimum", type = CommonConstants.TL, longValue = Long.MIN_VALUE)
    private static long intervalMinimum;

    @DefaultValue(key = "tcpcc", value = "tcpcc.sh",
            comment = "#shell for count tcp connection")
    private static String tcpCcScript;

    /**
     * 验签provider
     */
    @DefaultValue(key = "verifyprovider", value = AlgorithmConsts.INFOSEC_PROVIDER,
            title = "##########JCE Provider Properties############################")
    private static String verifyProvider;
    /**
     * 签名provide
     */
    @DefaultValue(key = "signprovider", value = AlgorithmConsts.INFOSEC_PROVIDER)
    private static String signProvider;
    /**
     * 公钥加密
     */
    @DefaultValue(key = "encryptprovider", value = AlgorithmConsts.INFOSEC_PROVIDER)
    private static String encryptProvider;
    /**
     * 私钥解密
     */
    @DefaultValue(key = "decryptprovider", value = AlgorithmConsts.INFOSEC_PROVIDER)
    private static String decryptProvider;
    /**
     * 对称加解密
     */
    @DefaultValue(key = "symm.provider", value = AlgorithmConsts.INFOSEC_PROVIDER)
    private static String symmProvider;

    /**
     * 使用p11还是jce
     * 是否使用硬件做签名运算。配hard适用于卫士通卡。5.5.30后不支持
     */
    @Deprecated
    @DefaultValue(key = "algmode", value = "soft", title = "##########AlgMode Properties###############################")
    private static String algMode;

    @DefaultValue(key = "usehardkeystore", type = CommonConstants.TB,
            comment = "#if store the sm2 keys into the crypto card or store keys into hsm")
    private static boolean useHardKeyStore;

    @DefaultValue(key = "hardkeystore.privatekeyalg", disable = "jce:SwxaJCE",
            comment = "#means use SwxaJCE as provider,only when usehardkeystore=yes it works")
    private static String privateKeyAlg;

    @DefaultValue(key = "hardkeystore.device", disable = "FisherManCryptoCard",
            comment = "#hard crypto device name( FisherManCryptoCard )")
    private static String hardKeyStoreDevice;

    @DefaultValue(key = "hardkeystore.backuppassword", disable = "11111111",
            comment = "#A password for hard keys backup and recover")
    private static String hardKeyStoreBackupPassword;

    // PDF
    @DefaultValue(key = "pdfpermission", title = "##########PDF Properties####################################",
            comment = "#Permissions of encripted pdf file:ASSEMBLY,COPY,DEGRADED_PRINTING,FILL_IN," +
                    "MODIFY_ANNOTATIONS,MODIFY_CONTENTS,PRINTING,SCREENREADERS\n#Split by ','.\n")
    private static String pdfPermission;

    @DefaultValue(key = "crlloadmode", value = "all",
            title = "##########CRL Properties####################################",
            comment = "#crl load mode , \"all\" or \"realtime\"")
    private static String crlLoadMode;

    @DefaultValue(key = "crlcleantimes", value = "2",
            comment = "#when clean the crl catches , hour of day , split by \",")
    private static String tmpCrlCleanTimes;


    @DefaultValue(key = "reloadcrlinterval", type = CommonConstants.TL, longValue = 300000,
            comment = "#the interval to reload the crl file(ms)")
    private static long reloadCRLInterval;


    @DefaultValue(key = "inblacklist", type = CommonConstants.TB,
            title = "##########PBC Properties####################################",
            comment = "#if the bank in blacklist while it was added the first time")
    private static boolean inBlackList;

    @DefaultValue(key = "ischeckbankid", type = CommonConstants.TB, boolValue = true,
            comment = "#is the bankid must match the subject dn")
    private static boolean isCheckBankID;

    @DefaultValue(key = "supportsm2", type = CommonConstants.TB,
            title = "##########SM2 Properties####################################",
            comment = "#if this system support sm2")
    private static boolean supportsm2;

    @DefaultValue(key = "usehardalg", value = "false",
            comment = "#if use the hard alg")
    private static String useHardAlg;


    @DefaultValue(key = "algprovider", comment = "#provider")
    private static String sm2Provider;

    @DefaultValue(key = "encryptusec", type = CommonConstants.TB,
            comment = "#encrypt use c implement algorithm")
    private static boolean isUsingCImp;

    @DefaultValue(key = "defaultsm2p10alg", value = "SM3withSM2",
            comment = "#the default alg while generate p10 request")
    private static String defaultSM2P10Alg;

    @DefaultValue(key = "sm3pucid",
            comment = "#the default value of SM3 pucid. plaintext or base64 text.(111111 or base64,ABe=ABe=)")
    private static String SM3CertpucIDString;

    @DefaultValue(key = "sm3p10puid")
    private static String SM3P10PucIDString;

    @DefaultValue(key = "sm3signpucid")
    private static String SM3SignpucIDString;

    @DefaultValue(key = "sm3ocspucid")
    private static String SM3OCSPPucIDString;

    @DefaultValue(key = "sm2cache", type = CommonConstants.TB,
            comment = "#if cache the result of sm2 computation")
    private static boolean sm2Cache;

    @DefaultValue(key = "sm2cachesize", type = CommonConstants.TI)
    private static int sm2CacheSize;

    @DefaultValue(key = "sm2signgear", value = "0/1",
            comment = "#gear for control the speed sm2 sign compute.(number of return without compute/number of return with compute)")
    private static String sm2SignGear;

    @DefaultValue(key = "sm2verifygear", value = "0/1",
            comment = "#gear for control the speed sm2 verify compute.(number of return without compute/number of return with compute)")
    private static String sm2VerifyGear;

    @DefaultValue(key = "envelopcache", type = CommonConstants.TB)
    private static boolean envelopCache;

    @DefaultValue(key = "envelopcachesize", type = CommonConstants.TI)
    private static int envelopCacheSize;

    @DefaultValue(key = "encryptgear", value = "0/1",
            comment = "#gear for control the speed sm2 encrypt compute.(number of return without compute/number of return with compute)")
    private static String encryptGear;

    @DefaultValue(key = "decryptgear", value = "0/1",
            comment = "#gear for control the speed sm2 decrypt compute.(number of return without compute/number of return with compute)")
    private static String decryptGear;

    @DefaultValue(key = "integerunsigned", type = CommonConstants.TB, boolValue = true,
            comment = "#If trade the SM2 signature result as an unsigned number")
    private static boolean integerUnsigned;

    /**
     * 国密公钥运算是否使用加密卡，包括验签名和解密。（只适用于信创版本签名服务器，非信创版本不可修改）
     * @since 20200902
     */
    @DefaultValue(key = "gmpublicalgusehsm", type = CommonConstants.TB,
            comment = "#if GM publickey algrithms use HSM")
    private static boolean GMPublicAlgUseHSM;

    @DefaultValue(key = "encryptcardworkingmessagequeue", type = CommonConstants.TI, intValue = 1,
            comment = "#The number of thread queues calling the encrypted card when using the encrypted card")
    private static int encryptCardWorkingMessageQueue;

    /**
     * 生成P7包时是否包含证书链
     */
    @DefaultValue(key = "", type = CommonConstants.TB,
            title = "###########PKCS7 Properties#################################")
    private static boolean withCertChain;

    @DefaultValue(key = "rsaencusingq7", type = CommonConstants.TB,
            comment = "#RSA encrytion algorithm, enveloped data type OID using Q7.")
    private static boolean rsaEncUsingQ7;

    @DefaultValue(key = "sm2encusingq7", type = CommonConstants.TB, boolValue = true,
            comment = "#SM2 encryption algorithm, enveloped data type OID using Q7.")
    private static boolean sm2EncUsingQ7;

    @DefaultValue(key = "rsasignusingq7", type = CommonConstants.TB,
            comment = "#If using Q7 as the standard while generate RSA signature.")
    private static boolean rsaSignUsingQ7;

    @DefaultValue(key = "sm2signusingq7", type = CommonConstants.TB, boolValue = true,
            comment = "#If using Q7 as the standard while generate SM2 signature.")
    private static boolean sm2SignUsingQ7;

    /**
     * 暂时没用到。解析时候不解析
     */
    @DefaultValue(key = "", type = CommonConstants.TB, boolValue = true,
            comment = "#If using Q7 as the standard while generate EC signature.")
    private static boolean ecSigUsingQ7;

    @DefaultValue(key = "ecencusingq7", type = CommonConstants.TB,
            comment = "#EC encrytion algorithm, enveloped data type OID using Q7.")
    private static boolean ecEncUsingQ7;

    @DefaultValue(key = "ecsignuseecalgwithp7", type = CommonConstants.TB,
            comment = "#EC sign P7 algorithm, enc alg type OID using ec alg.")
    private static boolean ECSignUseECAlgWithP7;

    @DefaultValue(key = "p7verifysupportauthattrs", type = CommonConstants.TB, boolValue = true,
            comment = "#If support authenticateAttributes while verify the SignedData.")
    private static boolean p7VerifySupportAuthAttrs;

    @DefaultValue(key = "p7verifywithlength", type = CommonConstants.TB,
            comment = "#If support length while verify the SignedData.")
    private static boolean p7verifyWithLength;

    @DefaultValue(key = "iscachecert", type = CommonConstants.TB, boolValue = true,
            comment = "#If cache the verify result of certs")
    private static boolean isCacheCert;

    @DefaultValue(key = "isverifycertchain", type = CommonConstants.TB, boolValue = true,
            comment = "#If support the verify of cert chain")
    private static boolean isVerifyCertChain;

    @DefaultValue(key = "issupportissuerkid", type = CommonConstants.TB, boolValue = true,
            comment = "#issupport issuerkid")
    private static boolean isSupportIssuerKid;

    /**
     * 是否自动重新加载资源
     */
    @DefaultValue(key = "isautoreloadresources", type = CommonConstants.TB,
            title = "###########RESOURCE SYNC Properties#########################")
    private static boolean isAutoReloadResources;

    @DefaultValue(key = "resourcereloadinterval", type = CommonConstants.TL, longValue = 60 * 60 * 1000)
    private static long resourceReloadInterval;


    @DefaultValue(key = "isautounzip", type = CommonConstants.TB,
            title = "###############PROCESSOR Properties#########################",
            comment = "#if netsign processors auto unzip the crypto or plain text, they maybe zipped by NetSign(COM)")
    private static boolean isAutoUnzip;

    @DefaultValue(key = "isreturnverifyresult", type = CommonConstants.TB, boolValue = true,
            comment = "#if the verify processors returns the certificate info and plain, only for performance test")
    private static boolean isReturnVerifyResult;

    @DefaultValue(key = "isreturnsignresult", type = CommonConstants.TB, boolValue = true)
    private static boolean isReturnSignResult;

    /**
     * 加密机版本新增 导入/生成对称密钥是否检查密钥、算法的正确性、导入非对称密钥是否检查密钥对
     */
    @DefaultValue(key = "ischeckmatch", type = CommonConstants.TB,
            comment = "#import/generate symmkey/asymmkey processors check keyWithAlg/keypair match or not")
    private static boolean isCheckMatch;

    @DefaultValue(key = "klbsignouterfields", type = CommonConstants.TB, boolValue = true,
            title = "##########Unstandard Signature Properties##################",
            comment = "#Double hash signature for KunLun bank , if sign on outer \"Files\" node in xml")
    private static boolean KLBSignOuterFields;

    /**
     * below
     * @since 5.5.40.12
     */
    @DefaultValue(key = "checkweekalg", type = CommonConstants.TB, boolValue = true,
            title = "#############Week Algorithm Properties#####################",
            comment = "#If check the week algorithms.")
    private static boolean checkWeekAlg;
    /**
     * 是否收集交易数据写在数据库里
     * @since tips
     */
    @DefaultValue(key = "", type = CommonConstants.TB,
            title = "#############firebird DB#################################")
    private static boolean isCollectData;

    /**
     * 自动GC时间间隔，测试参数，0为不进行GC
     * @since bjcp1.2
     */
    @DefaultValue(key = "autogcinterval", type = CommonConstants.TI,
            title = "#############Auto GC Interval#####################")
    private static int autoGCInterval;

    @DefaultValue(key = "genkeypairgear", type = CommonConstants.TI, intValue = 1,
            comment = "#Generate a real-scene certificate key pair. 1/n of all key pairs")
    private static int genKeyPairGear;

    /**
     * 非对称密钥延迟加载
     * 为true时候仅当为分离模式，且未开启同步时才生效
     * @since 5.5.40.12 patch31 黑龙江CA
     */
    @DefaultValue(key = "lazy.load.asymm.key", type = CommonConstants.TB,
            comment = "#start keypair lazy load")
    private static boolean lazyLoadAsymmKey;

    /**
     * 使用密钥池
     * sm2密钥池的容量
     * @since 5.5.40.12 patch32.1 浦发银行 2019-12-12
     */
    @DefaultValue(key = "sm2.pool.size", type = CommonConstants.TI,
            title = "############Keypair Pool Properties#######################")
    private static int sm2PoolSize;
    /**
     * RSA1024密钥池的容量
     */
    @DefaultValue(key = "rsa1024.pool.size", type = CommonConstants.TI)
    private static int rsa1024PoolSize;
    /**
     * RSA2048密钥池的容量
     */
    @DefaultValue(key = "rsa2048.pool.size", type = CommonConstants.TI)
    private static int rsa2048PoolSize;

    /**
     * 网联平台是否每次加密都产生随机密钥
     */
    @DefaultValue(key = "wangliangenrandomkey", type = CommonConstants.TB,
            comment = "#Whether the network connection platform generates a random key every time it encrypts")
    private static boolean wanglianGenRandomKey;

    /**
     * 强制进行gc
     */
    @DefaultValue(key = "forcegc", type = CommonConstants.TB,
            comment = "#Whether to force gc")
    private static boolean forceGC;

    /**
     * 强制GC的另一个触发条件，老生代占比
     */
    @DefaultValue(key = "oldgenusedratio", type = CommonConstants.TI,
            comment = "#Another triggering condition for forcing GC, the proportion of aging generation")
    private static int oldGenUsedRatio;

    /**
     * @since 5.5.40.12 patch15
     */
    @DefaultValue(key = "isDeleteRAWCert", type = CommonConstants.TB,
            comment = "#Whether to Delete RAWCert")
    private static boolean isDeleteRAWCert = true;
    /**
     * 验国密签名前是否检查公钥合法性
     * @since 5.5.40.12 patch16
     */
    @DefaultValue(key = "ischecksm2pubk", type = CommonConstants.TB, boolValue = true,
            comment = "#Whether to check the legitimacy of the public key before verifying the national secret signature")
    private static boolean isCheckSM2Pubk;
    /**
     * 是否发送notice
     * @since 5.5.40.12 patch16
     */
    @DefaultValue(key = "issendnotice", type = CommonConstants.TB,
            comment = "#Whether to send notice")
    private static boolean isSendNotice;

    @DefaultValue(key = "nocheckbankid", value = "ECDS",
            comment = "#When uploading the certificate, the bankId starting with this character is not checked")
    private static String checkBankIdWhiteList;

    /**
     * 证书文件是否单独存储
     * @since 5.5.40.12 patch31 黑龙江CA
     */
    @DefaultValue(key = "extract.cert.file", type = CommonConstants.TB,
            comment = "#Whether the certificate file is stored separately")
    private static boolean extractCertFile;
    /**
     * keypair列表索引是否使用CN DN,默认开启，开启后可能会造成索引冲突，风险自担
     * @since 5.5.40.12 patch31 黑龙江CA
     */
    @DefaultValue(key = "use.dn.and.cn.index", type = CommonConstants.TB, boolValue = true,
            comment = "# keypair list index uses CN/DN, default enable. it may cause index conflicts at your own risk")
    private static boolean useCnAndDnIndex;
    /**
     * 线程池自定义线程数
     */
    @DefaultValue(key = "thread.count.4.keypair.pool", type = CommonConstants.TI,
            comment = "#Thread pool custom threads")
    private static int threadCount4KeyPairPool;
    /**
     * 开启加密卡同步锁
     */
    @DefaultValue(key = "lock4cryptocard", type = CommonConstants.TB, boolValue = true,
            comment = "#Open the encryption card synchronization lock")
    private static boolean lock4CryptoCard;

    /**
     * 兴业银行加密库路径
     * 2020/03/30
     */
    @DefaultValue(key = "lib.industrial.bank.crypto.path",
            comment = "#Industrial Bank encrypted library path")
    private static String libIndustrialBankCryptoPath;

    /**
     * 密钥池配置
     * @since 5.5.40 WCS1.2
     * @since 合并微信开户项目 20191028
     */
    @DefaultValue(key = "genrsa1024poolsize", type = CommonConstants.TI,
            title = "#############WCS Extend Properties#####################")
    private static int genRSA1024PoolSize;

    @DefaultValue(key = "genrsa1024threadcount", type = CommonConstants.TI)
    private static int genRSA1024ThreadCount;

    @DefaultValue(key = "genrsa2048poolsize", type = CommonConstants.TI)
    private static int genRSA2048PoolSize;

    @DefaultValue(key = "genrsa2048threadcount", type = CommonConstants.TI)
    private static int genRSA2048ThreadCount;

    @DefaultValue(key = "wcsencpassword", value = "123456")
    private static String wechartstockEncpassword;

    @DefaultValue(key = "cert.sn.with0", type = CommonConstants.TB,
            title = "# whether support the serial number carries 0 when the serial number is used",
            comment = "false means without 0")
    private static boolean snWith0;

    /**
     * 设置资源同步类序列号
     * 资源同步时选择是否是patch22之前的版本还是之后的版本
     * 默认为新版本
     */
    @DefaultValue(key = "isnewserialversionuid", type = CommonConstants.TB, boolValue = true,
            comment = "#chose new version or old version serialVersionUID when syncing")
    private static boolean isNewSerialVersionUID;

    /**
     * 加密证书验签
     */
    @DefaultValue(key = "enc.cert.for.sign", type = CommonConstants.TB,
            comment = "#Certificate group configuration items")
    private static boolean encCertForSign;

    /**
     * @author Hoary.Huang
     * @return 产生P10 时候的空节点是否保留。true保留，false不保留
     * 适用于RSA
     * @since 5.5.40.16 2020.12.30
     */
    @DefaultValue(key = "p10.rsa.null", type = CommonConstants.TB, boolValue = true,
            title = "#keep null node while generate RSA P10, false quit/true keep")
    private static boolean p10RsaWithNull;

    /**
     * @author Hoary.Huang
     * @return 产生P10 时候的空节点是否保留。true保留，false不保留
     * 适用于 SM2
     * @since 5.5.40.16 2020.12.30
     */
    @DefaultValue(key = "p10.sm2.null", type = CommonConstants.TB, boolValue = true,
            comment = "#keep null node while generate SM2 P10, false quit/true keep")
    private static boolean p10Sm2WithNull;

    @DefaultValue(key = "asymm.encrypt.syn", type = CommonConstants.TB,
            comment = "#Whether to synchronize key for asymmetric encryption (default false:not synchronized)")
    private static boolean asymmEncryptSyn;

    @DefaultValue(key = "asymm.decrypt.syn", type = CommonConstants.TB,
            comment = "#Whether to synchronize key for asymmetric decrypt (default false:not synchronized)")
    private static boolean asymmDecryptSyn;

    @DefaultValue(key = "asymm.decrypt.support.bank.code", type = CommonConstants.TB,
            comment = "#Whether decryption supports bankId (default is true, support)")
    private static boolean decryptSupportBankCode;
    /**
     * 财政部：解数字信封验证书
     */
    @DefaultValue(key = "decrypt.enveloped.check.cert", type = CommonConstants.TB,
            comment = "#Ministry of Finance: verify cert while decrypt envelope.default not")
    private static boolean decryptEnvelopeCheckCert;

    @DefaultValue(key = "mode.sdf", type = CommonConstants.TB,
            comment = "#Whether to enable SDF mode")
    private static boolean sdfMode;

    @DefaultValue(key = "p7.discard.null", type = CommonConstants.TB,
            comment = "keep null node or drop while make p7")
    private static boolean p7WithNull;

    /**
     * @since 交行 9152需求
     * 说明: 只获取一次，所以可以不用set
     */
    @DefaultValue(key = "query.loader", value = "default",
            comment = "#Requirement for Bank of Communications 9152: Can I find the certificate closest to the system time based on the certificate subject")
    private static String queryLoader;

    @DefaultValue(key = "subject.query", type = CommonConstants.TB)
    private static boolean subjectQuery;

    @DefaultValue(key = "pbe.SKF.alg", value = "PBEWithSHA256And256BitAES-CBC-BC",
            title = "#PBE alg param, CSSP HTTP export KEK and import KEK")
    private static String pbeSKFAlg;

    @DefaultValue(key = "pbe.salt", value = "PBESalt")
    private static String pbeSalt;

    @DefaultValue(key = "pbe.iteration", type = CommonConstants.TI, intValue = 10)
    private static int pbeIteration;

    @DefaultValue(key = "pbe.digest.alg", value = "SHA1")
    private static String pbeDigestAlg;

    @DefaultValue(key = "pbe.provider", value = AlgorithmConsts.INFOSEC_PROVIDER)
    private static String pbeProvider;

    @DefaultValue(key = "pbe.symm.alg", value = AlgorithmConsts.AES_CBC_PKCS7PADDING)
    private static String pbeSymmAlg;

    @DefaultValue(key = "pbe.symm.IV", value = "1234567812345678")
    private static String pbeSymmIV;

    /**
     * 同步支持批量同步，此时需要关闭启动时同步
     */
    @DefaultValue(key = "start.syn.batch", type = CommonConstants.TB, boolValue = true,
            comment = "#Batch synchronization, turn off synchronization on startup")
    private static boolean synBatch;

    @DefaultValue(key = "p10.cfca.p9Attribute", type = CommonConstants.TB)
    private static boolean p10CFCAWithAttibute;

    @DefaultValue(key = "check.oscca.standards", type = CommonConstants.TB)
    private static boolean checkOSCCAStandards4PBC2G;

    @DefaultValue(key = "check.sm2.oscca.standards", type = CommonConstants.TB, boolValue = true)
    private static boolean checkSM2OSCCAStandards4PBC2G;

    @DefaultValue(key = "", type = CommonConstants.TB,
            comment = "#Whether to use external keys for card operations")
    private static boolean isExtKeyUseCard = true;

    @DefaultValue(key = "useCwithSM3", type = CommonConstants.TB,
            comment = "#Using C for SM3 operations")
    private static boolean isUsingCSM3;

    /**
     * 同步关联服务器定时检测默认超时时间,超过此时间认为关联服务器任务不可用。退出本次任务
     * 加这个参数是因为防止设置超时时间过大，导致长时间不返回导致队列无限增大
     * 设置超过15秒就任务设备为下线状态
     */
    @DefaultValue(key = "syn.scheduled.service.timeout", type = CommonConstants.TL, longValue = 15000,
            comment = "#default timeout if associated server timed detection is considered unavailable for associated server tasks beyond this time. Exiting this task with this parameter is to prevent setting the timeout time to be too long, resulting in an infinite increase in queue size. If timeout exceed 15 seconds, the task device will be offline.")
    private static long synScheduledServiceTimeOut;

    @DefaultValue(key = "genrandomusecard", type = CommonConstants.TB,
            comment = "#gen random with card")
    private static boolean genRandomUseCard;

    @DefaultValue(key = "regenerateCryptoTextForSM2", type = CommonConstants.TB)
    private static boolean regenerateCryptoTextForSM2;

    @DefaultValue(key = "external.key.operation.crypto.card", type = CommonConstants.TB, boolValue = true)
    private static boolean caviumUseSoftWhenFailed;

    /**
     * 是否记录进入processor的时间
     */
    @DefaultValue(key = "isrecordingstarttime", type = CommonConstants.TB)
    private static boolean isRecordingStartTime;

    @DefaultValue(key = "envelopsm4oiduseunstandard", type = CommonConstants.TB)
    private static boolean envelopSM4OIDUseUnStandard;

    // 以下数据不保存

    @DefaultValue(key = "isissuerdncasematch", type = CommonConstants.TB, boolValue = true)
    private static boolean issuerDNCaseMatch;

    @DefaultValue(key = "needcheckosccastandards", type = CommonConstants.TB)
    private static boolean needCheckOSCCAStandards;

    @DefaultValue(key = "ecsigmustq7", type = CommonConstants.TB)
    private static boolean ECSigMustQ7;

    @DefaultValue(key = "sm2sigmustq7", type = CommonConstants.TB)
    private static boolean SM2SigMustQ7;

    @DefaultValue(key = "rsasigmustq7", type = CommonConstants.TB)
    private static boolean RSASigMustQ7;

    @DefaultValue(key = "sm2sigmustseq", type = CommonConstants.TB)
    private static boolean SM2SigMustSeq;

    @DefaultValue(key = "sm2sigmustunsignedint", type = CommonConstants.TB)
    private static boolean SM2SigMustUnsignedInt;

    @DefaultValue(key = "sm2sigmustsignedint", type = CommonConstants.TB)
    private static boolean SM2SigMustSignedInt;

    /**
     * @since 5.6.50.4 之后的项目
     * @date 2022.08.19 11.18
     * @author hoary
     * 吉大的P10编码，证书主题全都使用UTF8String
     */
    @DefaultValue(key = "p10.subject.encode.jida", type = CommonConstants.TB)
    private static boolean p10SubjectJida;

    /**
     * 系统模式
     * mode.system = csspcloud
     * 为使此配置兼容未来可能出现的其他模式，使用string类型
     */
    @DefaultValue(key = "mode.system")
    private static String systemMode;

    /**
     *  增加CRL服务器健康检查属性
     * @author zhaoxin
     * @since 2021/09/08
     */
    /**
     * 启用健康检查
     */
    @DefaultValue(key = "enablehealthcheck", type = CommonConstants.TB)
    private static boolean enableHealthCheck;
    /**
     * 检查间隔
     */
    @DefaultValue(key = "checkinterval", type = CommonConstants.TI, intValue = 60)
    private static int checkInterval;
    /**
     * 连接超时
     */
    @DefaultValue(key = "conntimeout", type = CommonConstants.TI, intValue = 3000)
    private static int connTimeout;
    /**
     * 读取超时
     */
    @DefaultValue(key = "readtimeout", type = CommonConstants.TI, intValue = 3000)
    private static int readTimeout;
    /**
     * 重试此时
     */
    @DefaultValue(key = "retrycount", type = CommonConstants.TI, intValue = 3)
    private static int retryCount;

    @DefaultValue(key = "syslogsystem", value = "local0")
    private static String syslogSystem;

    @DefaultValue(key = "syslogaccess", value = "local1")
    private static String syslogAccess;

    @DefaultValue(key = "syslogdebug", value = "local2")
    private static String syslogDebug = "local2";

    /**
     * @since 2013-12-05(create) LH.
     */
    @DefaultValue(key = "subFilter", value = "adbe.pkcs7.detached")
    public static String subFilter;

    /**
     * 根据需要指定默认的签名注释文字和签章文件
     */
    @DefaultValue(key = "signnotation")
    public static String signNotation;

    @DefaultValue(key = "stampfile")
    public static String stampFile;


    @DefaultValue(key = "checkvalidity", type = CommonConstants.TB, boolValue = true)
    private static boolean isCheckCertValidity;

    /**
     * 云服务主类
     */
    @DefaultValue(key = "yun.config.path")
    private static String hgfPath;


    static{
        jmxLevelSet = new HashSet<>();
        jmxLevelSet.add(JMX_MONITOR_LEVEL_NONE);
        jmxLevelSet.add(JMX_MONITOR_LEVEL_SYSTEM);
        jmxLevelSet.add(JMX_MONITOR_LEVEL_FULL);
    }

    public static void load(String confFile) {
        try {
            prop = ProReflectUtils.load(confFile, ExtendedConfig.class, null);
            prop.list(System.out);
            key2FieldMap = ProReflectUtils.key2FieldName(ExtendedConfig.class);
        } catch (Exception e) {
            ConsoleLogger.logException(e);
        }
        // 其他的操作；get set方法中不写业务逻辑，提取到这里
        extraOperation();
    }

    /**
     * 拼接字符串，生成extension.properties
     *
     * @param filepath
     */
    public synchronized static void save(String filepath) {
        try {
            // 原来没有的，不生成。硬要的, 没有就留空的。保证在prop里边存在就行
            addKey2Prop("encoding");
            addKey2Prop("crlLoadMode");
            addKey2Prop("algprovider");
            addKey2Prop("sm3pucid");
            addKey2Prop("sm3signpucid");
            addKey2Prop("sm3p10puid");
            addKey2Prop("sm3ocspucid");
            addKey2Prop("encryptgear");
            addKey2Prop("decryptgear");
            addKey2Prop("lib.industrial.bank.crypto.path");
            addKey2Prop("usehardalg");
            addKey2Prop("pdfpermission");

            // 没有值就加上注释的
            addKey2Prop("hardkeystore.backuppassword");
            addKey2Prop("hardkeystore.privatekeyalg");
            addKey2Prop("hardkeystore.device");

            // 经过转换处理的
            reversePdfPermission();
            reverseCrlCleanTimes();
            reverseSm2HardAlg();
            reverseBankId();

            boolean off = isTcpCheckOff();
            if(off){
                prop.remove("tcpcc");
            }
            StringBuilder buf = ProReflectUtils.saveObject2Pro(ExtendedConfig.class, null, prop);
            if (off) {
                buf.append("#tcpcc=bin/tcpcc.sh\n");
            }

            ConfigUtil.save(filepath, buf.toString().getBytes("GBK"), 3);
        } catch (Exception e) {
            ConsoleLogger.logException(e);
        }
    }

    /**
     * 拼接字符串，生成extension.properties
     *
     * 这是服务高级配置页面保存用到的函数, 只保存一项
     * @param filepath
     */
    public synchronized static void save(String filepath, String configName, String configValue) {

        String fieldName = key2FieldMap.get(configName);
        try {
            ProReflectUtils.changeItemValue(fieldName, configValue, ExtendedConfig.class, null);
        } catch (Exception e) {
            ConsoleLogger.logException(e);
        }
        save(filepath);
    }

    /**
     * 修改内存
     *
     * @param configName
     * @param configValue
     */
    public synchronized static boolean set2Mem(String configName, String configValue) {

        String fieldName = key2FieldMap.get(configName);
        try {
            ProReflectUtils.changeItemValue(fieldName, configValue, ExtendedConfig.class, null);
            extraOperation();
        } catch (Exception e) {
            ConsoleLogger.logException(e);
            return false;
        }
        return true;
    }

    private static void extraOperation(){
        sm2UseHardKeyStore = useHardKeyStore;
        nocheckBankid = checkBankIdWhiteList.split(SEP_COMMA);
        sm3CertPuid = loadByteArray(SM3CertpucIDString, null);
        sm3SignPuid = loadByteArray(SM3SignpucIDString, null);
        sm3P10Puid = loadByteArray(SM3P10PucIDString, null);
        sm3OCSPPuid = loadByteArray(SM3OCSPPucIDString, null);
        crlCleanTimes = loadCrlCleanTimes();
        fixAllLog();
        fixJmx();
        fixAutoGcInterval();
        fixProvider();
        fixPdfConf();
        fixSm2HardAlg();
        initLogConfig();
        setSerialVersionUID(isNewSerialVersionUID);
        add2CaviumSystemProperty(String.valueOf(caviumUseSoftWhenFailed));
        ServerConfig.setCsspCloudMode("csspcloud".equals(systemMode));
    }

    private static void fixAllLog(){
        CryptoUtil.debug = isDebug;
        cn.com.infosec.netsign.der.util.ConsoleLogger.isDebug = isDebug;
        // 2020-06-11 为isfj中的日志debug赋值
        cn.com.infosec.util.ConsoleLogger.isDebug = isDebug;
    }
    private static void fixJmx(){
        if(!jmxLevelSet.contains(jmxMonitorLevel)){
            jmxMonitorLevel = JMX_MONITOR_LEVEL_NONE;
        }
    }

    private static void fixAutoGcInterval(){
        autoGCInterval = autoGCInterval * 60 * 1000;
    }

    private static void fixProvider(){
        if (verifyProvider.indexOf(SEP_COMMA) > 0) {
            verifyProviders = verifyProvider.split(SEP_COMMA);
            verifyProvider = verifyProviders[0];
        }
        if (signProvider.indexOf(SEP_COMMA) > 0) {
            signProviders = signProvider.split(SEP_COMMA);
            signProvider = signProviders[0];
        }
        if(AlgorithmConsts.PROVIDER_SWXA_ALG.equals(privateKeyAlg)
                && sm2UseHardKeyStore && DataUtils.isEmpty(hardKeyStoreDevice)){
            signProvider = AlgorithmConsts.PROVIDER_SWXA;
            decryptProvider = AlgorithmConsts.PROVIDER_SWXA;
        }

    }

    private static void fixPdfConf(){
        if (!"".equals(pdfPermission.trim())) {
            String[] pieces = pdfPermission.split(SEP_COMMA);
            pdfPermissions = new int[1];
            for (String piece : pieces) {
                int r = getPermissionValue(piece);
                if (r > 0) {
                    pdfPermissions[0] |= r;
                }
            }
        }
    }
    private static void fixSm2HardAlg() {
        String tmp = useHardAlg;
        if (tmp.contains(SEP_COMMA)){
            String[] pieces = tmp.split(SEP_COMMA);
            sm2SignUseHardALG = ("YES".equals(pieces[0]) || "TRUE".equals(pieces[0]));
            sm2VerifyUseHardALG = ("YES".equals(pieces[1]) || "TRUE".equals(pieces[1]));
        } else {
            sm2SignUseHardALG = sm2VerifyUseHardALG = ("YES".equals(tmp) || "TRUE".equals(tmp));
        }
    }

    private static void reverseSm2HardAlg(){
        if (sm2SignUseHardALG == sm2VerifyUseHardALG) {
            useHardAlg = "" + sm2SignUseHardALG;
        } else {
            useHardAlg = sm2SignUseHardALG + SEP_COMMA + sm2VerifyUseHardALG;
        }
    }

    private static void reverseBankId(){
        StringBuilder banKids = new StringBuilder();
        for (int i = 0; i < nocheckBankid.length; i++) {
            String punct = ",";
            banKids.append(nocheckBankid[i]);
            if (i != nocheckBankid.length - 1) {
                banKids.append(punct);
            }
        }
        checkBankIdWhiteList = banKids.toString();
    }

    private static void reverseCrlCleanTimes(){
        int[] crlct = crlCleanTimes;
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < crlct.length; i++) {
            String punct = ",";
            buf.append(crlct[i]);
            if (i != crlct.length - 1) {
                buf.append(punct);
            }
        }
        tmpCrlCleanTimes = buf.toString();
    }

    private static void reversePdfPermission(){
        StringBuilder buf = new StringBuilder();
        if (pdfPermissions.length > 0 && pdfPermissions[0] != -1) {
            String punct = ",";
            int[] intpers = pdfPermissions;
            for (int i = 0; i < intpers.length; i++) {
                buf.append(parseInt2StringValue(intpers[i]));
                if (i != (intpers.length - 1)) {
                    buf.append(punct);
                }
            }
            buf.append("\n");
        }
        pdfPermission = buf.toString();
    }

    private static void initLogConfig() {
        // hoary add at 2020.04.22
        BasicLogConfig logConfig =
                BasicLogConfig.create().withPrintST(isPrintST).withDebug(isDebug).withSave(isSave)
                        .withNohupConfig(nohupLogConfig).withProjectID(projectID)
                        .withLogBuffer(logBuffer);
        BasicConfigManager.setLogConfig(logConfig);
        BasicExtensionConfig bec = BasicConfigManager.getBasicExtensionConfig();
        copyConfig2Basic(bec);
        BasicConfigManager.setBasicExtensionConfig(bec);
    }

    private static void setSerialVersionUID(boolean isNewSerialVersionUID) {
        if (versionConfig == null) {
            versionConfig = new SerialVersionConfig();
        }
        Properties prop;
        try {
            if (isNewSerialVersionUID) {
                prop = ProReflectUtils.loadProperties(newNewSerialVersionFile);
            } else {
                prop = ProReflectUtils.loadProperties(oldNewSerialVersionFile);
            }
            prop.list(System.out);
            versionConfig.setRawCertSynEmissaryUID(loadRawCertSynEmissaryUID(prop));
            versionConfig.setSynEmissaryUID(loadSynEmissaryUID(prop));
            versionConfig.setSynParametersUID(loadSynParametersUID(prop));
            versionConfig.setSynResultUID(loadSynResultUID(prop));
        } catch (IOException e) {
            ConsoleLogger.logString("no file found: configs/webuiConfig/newSerialVersionUID.properties");
        }
    }

    private static void copyConfig2Basic(BasicExtensionConfig bec) {
        bec.setRsaSignUsingQ7(rsaSignUsingQ7);
        bec.setRsaEncUsingQ7(rsaEncUsingQ7);
        bec.setSm2SignUsingQ7(sm2SignUsingQ7);
        bec.setSm2EncUsingQ7(sm2EncUsingQ7);
    }

    private static byte[] loadByteArray(String value, byte[] defValue) {
        try {
            if (value.startsWith("base64,")) {
                value = value.substring(7);
                return Base64.decode(value);
            } else {
                return value.getBytes("GBK");
            }
        } catch (Exception e) {
            return defValue;
        }
    }

    private static int[] loadCrlCleanTimes() {
        String timesStr = tmpCrlCleanTimes;
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

    private static void add2CaviumSystemProperty(String property) {
        // property
        System.setProperty("useSoftWhenCaviumUnavailable", property);
    }

    private static void addKey2Prop(String key){
        if(prop.containsKey(key)){
            return;
        }
        prop.put(key, "");
    }

    private static boolean isTcpCheckOff(){
        String num = ShellUtil.execShell(String.format("cat %s/extension.properties|grep '#tcpcc'|wc -l", SystemInfoConsts.configPath));
        if ("1".equals(num.trim())) {
            return true;
        }
        return false;
    }

    public static boolean isUsehardkeystore() {
        return sm2UseHardKeyStore;
    }

    public static boolean isEnvelopSignerIDUserKid() {
        return envelopeSignerIDUseKid;
    }

    public static boolean isSignAndEnvelopedEncSign() {
        return signAndEnvelopedEncSign;
    }

    public static boolean isSignAndEnvelopedDecSign() {
        return signAndEnvelopedDecSign;
    }

    public static String getSyslogProtocol() {
        return syslogProtocol;
    }

    public static String getSyslogProtocolSSLConfigPath() {
        return syslogProtocolSSLConfigPath;
    }

    public static boolean isSM2SignUsehardalg() {
        return sm2SignUseHardALG;
    }

    public static boolean isSM2VerifyUsehardalg() {
        return sm2VerifyUseHardALG;
    }

    public static SerialVersionConfig getVersionConfig() {
        return versionConfig;
    }

    public static String[] getVerifyProviders() {
        return verifyProviders;
    }

    public static String[] getSignProviders() {
        return signProviders;
    }

    public static String[] getNocheckBankid() {
        return nocheckBankid;
    }

    public static int[] getPDFPermissions() {
        return pdfPermissions;
    }

    public static int[] getCrlCleanTimes() {
        return crlCleanTimes;
    }

    public static byte[] getSM3pucID() {
        return sm3CertPuid;
    }

    public static byte[] getSm3P10Puid() {
        return sm3P10Puid;
    }

    public static byte[] getSM3SignpucID() {
        return sm3SignPuid;
    }

    public static byte[] getSM3OCSPPucid() {
        return sm3OCSPPuid;
    }

    public static int getBackLog() {
        return backLog;
    }

    public static boolean isSessionMonitorOpen() {
        return isSessionMonitorOpen;
    }

    public static int getMaxSessionPoolSize() {
        return maxSessionPoolSize;
    }

    public static int threadPoolCore() {
        return threadPoolCore;
    }

    public static int threadPoolMax() {
        return threadPoolMax;
    }

    public static int getThreadPoolQueue() {
        return threadPoolQueue;
    }

    public static boolean isCatchHandler() {
        return isCatchHandler;
    }

    public static int getLogBuffer() {
        return logBuffer;
    }

    public static boolean isLogRespTime() {
        return isLogRespTime;
    }

    public static long getLongBusinessTime() {
        return longBusinessTime;
    }

    public static String getNohupLogConfig() {
        return nohupLogConfig;
    }

    public static int getMaxReadThread() {
        return maxReadThread;
    }

    public static void setEncoding(String encoding) {
        ExtendedConfig.encoding = encoding;
    }

    public static String getEncoding() {
        return encoding;
    }

    public static boolean isPrintST() {
        return isPrintST;
    }

    public static boolean isDebug() {
        return isDebug;
    }

    public static boolean isSelfTest() {
        return selfTest;
    }

    public static int getProjectID() {
        return projectID;
    }

    public static boolean isSave() {
        return isSave;
    }

    public static String getJmxMonitorLevel() {
        return jmxMonitorLevel;
    }

    public static int getTaskQueueMax() {
        return taskQueueMax;
    }

    public static long getTaskQueueWatchInterval() {
        return taskQueueWatchInterval;
    }

    public static long getServiceInfoCollectInterval() {
        return serviceInfoCollectInterval;
    }

    public static long getQueryTime() {
        return queryTime;
    }

    public static long getIntervalMaximum() {
        return intervalMaximum;
    }

    public static long getIntervalMinimum() {
        return intervalMinimum;
    }

    public static String getEncryptProvider() {
        return encryptProvider;
    }

    public static String getDecryptProvider() {
        return decryptProvider;
    }

    public static String getSymmProvider() {
        return symmProvider;
    }

    public static String getAlgMode() {
        return algMode;
    }

    public static boolean isUseHardKeyStore() {
        return useHardKeyStore;
    }

    public static String getPrivateKeyAlg() {
        return privateKeyAlg;
    }

    public static String getHardKeyStoreDevice() {
        return hardKeyStoreDevice;
    }

    public static String getHardKeyStoreBackupPassword() {
        return hardKeyStoreBackupPassword;
    }

    public static String getCRLLoadMode() {
        return crlLoadMode;
    }

    public static long getReloadCRLInterval() {
        return reloadCRLInterval;
    }

    public static boolean isInBlackList() {
        return inBlackList;
    }

    public static boolean isCheckBankID() {
        return isCheckBankID;
    }

    public static boolean isSupportsm2() {
        return supportsm2;
    }

    public static String getUseHardAlg() {
        return useHardAlg;
    }

    public static String getSm2Provider() {
        return sm2Provider;
    }

    public static boolean isUsingCImp() {
        return isUsingCImp;
    }

    public static String getDefaultSM2P10Alg() {
        return defaultSM2P10Alg;
    }

    public static boolean isSm2Cache() {
        return sm2Cache;
    }

    public static int getSm2CacheSize() {
        return sm2CacheSize;
    }

    public static String getSm2SignGear() {
        return sm2SignGear;
    }

    public static String getSm2VerifyGear() {
        return sm2VerifyGear;
    }

    public static boolean isEnvelopCache() {
        return envelopCache;
    }

    public static int getEnvelopCacheSize() {
        return envelopCacheSize;
    }

    public static String getEncryptGear() {
        return encryptGear;
    }

    public static String getDecryptGear() {
        return decryptGear;
    }

    public static boolean isIntegerUnsigned() {
        return integerUnsigned;
    }

    public static boolean isGMPublicAlgUseHSM() {
        return GMPublicAlgUseHSM;
    }

    public static int getEncryptCardWorkingMessageQueue() {
        return encryptCardWorkingMessageQueue;
    }

    public static boolean isWithCertChain() {
        return withCertChain;
    }

    public static boolean isRsaEncUsingQ7() {
        return rsaEncUsingQ7;
    }

    public static boolean isSm2EncUsingQ7() {
        return sm2EncUsingQ7;
    }

    public static boolean isRSASignUsingQ7() {
        return rsaSignUsingQ7;
    }

    public static boolean isSM2SignUsingQ7() {
        return sm2SignUsingQ7;
    }

    public static boolean isEcSigUsingQ7() {
        return ecSigUsingQ7;
    }

    public static boolean isEcEncUsingQ7() {
        return ecEncUsingQ7;
    }

    public static boolean isECSignUseECAlgWithP7() {
        return ECSignUseECAlgWithP7;
    }

    public static boolean p7VerifySupportAuthAttrs() {
        return p7VerifySupportAuthAttrs;
    }

    public static boolean isP7verifyWithLength() {
        return p7verifyWithLength;
    }

    public static boolean isCacheCert() {
        return isCacheCert;
    }

    public static boolean isVerifyCertChain() {
        return isVerifyCertChain;
    }

    public static boolean isSupportIssuerKid() {
        return isSupportIssuerKid;
    }

    public static boolean isAutoReloadResources() {
        return isAutoReloadResources;
    }

    public static long getResourceReloadInterval() {
        return resourceReloadInterval;
    }

    public static boolean isAutoUnzip() {
        return isAutoUnzip;
    }

    public static boolean isReturnVerifyResult() {
        return isReturnVerifyResult;
    }

    public static boolean isReturnSignResult() {
        return isReturnSignResult;
    }

    public static boolean isCheckMatch() {
        return isCheckMatch;
    }

    public static boolean isKLBSignOuterFields() {
        return KLBSignOuterFields;
    }

    public static boolean isCheckWeekAlg() {
        return checkWeekAlg;
    }

    public static boolean isCollectData() {
        return isCollectData;
    }

    public static int getAutoGCInterval() {
        return autoGCInterval;
    }

    public static int getGenKeyPairGear() {
        return genKeyPairGear;
    }

    public static boolean isLazyLoadAsymmKey() {
        return lazyLoadAsymmKey;
    }

    public static int getSm2PoolSize() {
        return sm2PoolSize;
    }

    public static int getRsa1024PoolSize() {
        return rsa1024PoolSize;
    }

    public static int getRsa2048PoolSize() {
        return rsa2048PoolSize;
    }

    public static void setWangLianGenRandomKey(boolean wanglianGenRandomKey) {
        ExtendedConfig.wanglianGenRandomKey = wanglianGenRandomKey;
    }

    public static boolean isWanglianGenRandomKey() {
        return wanglianGenRandomKey;
    }

    public static boolean isForceGC() {
        return forceGC;
    }

    public static int getOldGenUsedRatio() {
        return oldGenUsedRatio;
    }

    public static boolean isDeleteRAWCert() {
        return isDeleteRAWCert;
    }

    public static boolean isCheckSM2Pubk() {
        return isCheckSM2Pubk;
    }

    public static boolean isSendNotice() {
        return isSendNotice;
    }

    public static String getCheckBankIdWhiteList() {
        return checkBankIdWhiteList;
    }

    public static boolean isExtractCertFile() {
        return extractCertFile;
    }

    public static boolean isUseCnAndDnIndex() {
        return useCnAndDnIndex;
    }

    public static int getThreadCount4KeyPairPool() {
        return threadCount4KeyPairPool;
    }

    public static boolean isLock4CryptoCard() {
        return lock4CryptoCard;
    }

    public static String getLibIndustrialBankCryptoPath() {
        return libIndustrialBankCryptoPath;
    }

    public static int getGenRSA1024PoolSize() {
        return genRSA1024PoolSize;
    }

    public static int getGenRSA1024ThreadCount() {
        return genRSA1024ThreadCount;
    }

    public static int getGenRSA2048PoolSize() {
        return genRSA2048PoolSize;
    }

    public static int getGenRSA2048ThreadCount() {
        return genRSA2048ThreadCount;
    }

    public static String getWechartstockEncpassword() {
        return wechartstockEncpassword;
    }

    public static boolean isSnWith0() {
        return snWith0;
    }

    public static boolean isNewSerialVersionUID() {
        return isNewSerialVersionUID;
    }

    public static boolean isEncCertForSign() {
        return encCertForSign;
    }

    public static boolean isP10RsaWithNull() {
        return p10RsaWithNull;
    }

    public static boolean isP10Sm2WithNull() {
        return p10Sm2WithNull;
    }

    public static boolean isAsymmEncryptSyn() {
        return asymmEncryptSyn;
    }

    public static boolean isAsymmDecryptSyn() {
        return asymmDecryptSyn;
    }

    public static boolean isDecryptSupportBankCode() {
        return decryptSupportBankCode;
    }

    public static boolean isDecryptEnvelopeCheckCert() {
        return decryptEnvelopeCheckCert;
    }

    public static boolean isSdfMode() {
        return sdfMode;
    }

    public static boolean isP7WithNull() {
        return p7WithNull;
    }

    public static String getQueryLoader() {
        return queryLoader;
    }

    public static boolean isSubjectQuery() {
        return subjectQuery;
    }

    public static String getPbeSKFAlg() {
        return pbeSKFAlg;
    }

    public static String getPbeSalt() {
        return pbeSalt;
    }

    public static int getPbeIteration() {
        return pbeIteration;
    }

    public static String getPbeDigestAlg() {
        return pbeDigestAlg;
    }

    public static String getPbeProvider() {
        return pbeProvider;
    }

    public static String getPbeSymmAlg() {
        return pbeSymmAlg;
    }

    public static String getPbeSymmIV() {
        return pbeSymmIV;
    }

    public static boolean isSynBatch() {
        return synBatch;
    }

    public static boolean isP10CFCAWithAttibute() {
        return p10CFCAWithAttibute;
    }

    public static boolean isCheckOSCCAStandards4PBC2G() {
        return checkOSCCAStandards4PBC2G;
    }

    public static boolean isCheckSM2OSCCAStandards4PBC2G() {
        return checkSM2OSCCAStandards4PBC2G;
    }

    public static boolean ExtKeyUseCard() {
        return isExtKeyUseCard;
    }

    public static boolean isUsingCSM3() {
        return isUsingCSM3;
    }

    public static long getSynScheduledServiceTimeOut() {
        return synScheduledServiceTimeOut;
    }

    public static boolean isGenRandomUseCard() {
        return genRandomUseCard;
    }

    public static boolean isRegenerateCryptoTextForSM2() {
        return regenerateCryptoTextForSM2;
    }

    public static boolean isCaviumUseSoftWhenFailed() {
        return caviumUseSoftWhenFailed;
    }

    public static boolean isRecordingStartTime() {
        return isRecordingStartTime;
    }

    public static boolean isEnvelopSM4OIDUseUnStandard() {
        return envelopSM4OIDUseUnStandard;
    }

    public static boolean isIssuerDNCaseMatch() {
        return issuerDNCaseMatch;
    }

    public static boolean isNeedCheckOSCCAStandards() {
        return needCheckOSCCAStandards;
    }

    public static boolean isECSigMustQ7() {
        return ECSigMustQ7;
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

    public static boolean isP10SubjectJida() {
        return p10SubjectJida;
    }

    public static String getSystemMode() {
        return systemMode;
    }

    public static boolean isEnableHealthCheck() {
        return enableHealthCheck;
    }

    public static int getCheckInterval() {
        return checkInterval;
    }

    public static int getConnTimeout() {
        return connTimeout;
    }

    public static int getReadTimeout() {
        return readTimeout;
    }

    public static int getRetryCount() {
        return retryCount;
    }

    public static String getSyslogSystem() {
        return syslogSystem;
    }

    public static String getSyslogAccess() {
        return syslogAccess;
    }

    public static String getSyslogDebug() {
        return syslogDebug;
    }

    public static String getSubFilter() {
        return subFilter;
    }

    public static String getSignNotation() {
        return signNotation;
    }

    public static String getStampFile() {
        return stampFile;
    }

    public static boolean isCheckCertValidity() {
        return isCheckCertValidity;
    }

    public static String getHgfPath() {
        return hgfPath;
    }

    public static String getShellFile(String name) {
        return prop.getProperty(name, "");
    }
}
