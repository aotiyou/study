package cn.com.infosec.tool;

import cn.com.infosec.ucypher.agent.sdf.UCypherSDF;
import cn.com.infosec.ucypher.agent.sdf.UCypherSDFDev;
import cn.com.infosec.ucypher.agent.sdf.UCypherSDFTool;

import java.io.File;
import java.io.FileReader;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

/**
 * @author infosec
 * @since 2025/9/24
 */
public class Agent {

    private static final String CFGFILE = "ucypheragent.properties";
    private static final String RESNAME = "ucypheragent";

    private static UCypherSDFDev udev = null;

    public static UCypherSDF agent = null;

    static {
        File file = new File(Agent.class.getResource("/").getPath()).getParentFile();
        String configFile = file.getAbsolutePath() + System.getProperty("file.separator") + CFGFILE;
        ResourceBundle res = null;
        try {
            res = readRes(configFile);
        } catch (Exception e) {
            throw new RuntimeException("Read file error", e);
        }
        udev = new UCypherSDFDev();
        setUCypherDEV(res, UCypherSDFDev.DEV_IP);
        setUCypherDEV(res, UCypherSDFDev.DEV_PORT);
        setUCypherDEV(res, UCypherSDFDev.DEV_CONNECT_TIMEOUT);
        setUCypherDEV(res, UCypherSDFDev.DEV_READ_TIMEOUT);
        setUCypherDEV(res, UCypherSDFDev.LOAD_MODE);
        setUCypherDEV(res, UCypherSDFDev.USER);
        setUCypherDEV(res, UCypherSDFDev.AUTHCODE);
        setUCypherDEV(res, UCypherSDFDev.TICKET);
        setUCypherDEV(res, UCypherSDFDev.POOLSIZE);
        setUCypherDEV(res, UCypherSDFDev.POOLKEEPALIVE);
        setUCypherDEV(res, UCypherSDFDev.SSL_ON);
        setUCypherDEV(res, UCypherSDFDev.SSL_PROVIDER);
        setUCypherDEV(res, UCypherSDFDev.SSL_PROTOCOL);
        setUCypherDEV(res, UCypherSDFDev.SSL_CIPHER_SUITES);
        setUCypherDEV(res, UCypherSDFDev.SSL_TRUST_X509PROVIDER);
        setUCypherDEV(res, UCypherSDFDev.SSL_TRUST_CERTPATH);
        setUCypherDEV(res, UCypherSDFDev.SSL_TRUST_MANAGER_FACTORY_ALG);
        setUCypherDEV(res, UCypherSDFDev.SSL_TRUST_MANAGER_FACTORY_PROVIDER);
        setUCypherDEV(res, UCypherSDFDev.SSL_TRUST_KEYSTORE_TYPE);
        setUCypherDEV(res, UCypherSDFDev.SSL_TRUST_KEYSTORE_PROVIDER);
        setUCypherDEV(res, UCypherSDFDev.SSL_TRUST_ENTRY_ALIAS);
        setUCypherDEV(res, UCypherSDFDev.SSL_CLIENT_CERT_MANAGER_FACTORY_ALG);
        setUCypherDEV(res, UCypherSDFDev.SSL_CLIENT_CERT_MANAGER_FACTORY_PROVIDER);
        setUCypherDEV(res, UCypherSDFDev.SSL_CLIENT_CERT_KEYSTORE_TYPE);
        setUCypherDEV(res, UCypherSDFDev.SSL_CLIENT_CERT_KEYSTORE_PROVIDER);
        setUCypherDEV(res, UCypherSDFDev.SSL_CLIENT_CERT_PATH);
        setUCypherDEV(res, UCypherSDFDev.SSL_CLIENT_CERT_CODE);
        setUCypherDEV(res, UCypherSDFDev.LOG_LEVEL);
        setUCypherDEV(res, UCypherSDFDev.LOG_COUNT);
        setUCypherDEV(res, UCypherSDFDev.LOG_MAX_SIZE);

        try {
            openSdf();
        } catch (Exception e) {
            throw new RuntimeException("Fail to open agent", e);
        }
    }

    public static UCypherSDF openSdf() throws Exception {
        agent = new UCypherSDF();
        int ret = agent.SDFOpenDevice(udev);
        if (ret != 0) {
            throw new RuntimeException("UCypher open device error, ret: " + ret);
        }

        ret = agent.SDFOpenSession();
        if (ret != 0) {
            throw new RuntimeException("UCypher open session error, ret: " + ret);
        }

        return agent;
    }

    private static void closeSdf() {
        agent.SDFCloseSession();
        agent.SDFCloseDevice();
    }

    private static ResourceBundle readRes(String configFile) throws Exception {
        String path = (configFile == null) ? UCypherSDFTool.class.getProtectionDomain().getCodeSource().getLocation().getPath() : configFile;
        File f = new File(path);
        if (!f.isDirectory()) {
            path = f.getParentFile().getAbsolutePath();
        }
        f = new File(path + "/" + CFGFILE);
        String cfgfile = null;
        if (f.exists()) {
            System.out.println("find " + CFGFILE + " in " + path);
            cfgfile = f.getAbsolutePath();
        } else {
            f = new File(CFGFILE);
            if (f.exists()) {
                System.out.println("find " + CFGFILE + " in ./");
                cfgfile = f.getAbsolutePath();
            }
        }
        ResourceBundle res = null;
        if (cfgfile != null) {
            FileReader in = null;
            try {
                in = new FileReader(cfgfile);
                res = new PropertyResourceBundle(in);
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        } else {
            res = ResourceBundle.getBundle(RESNAME);
        }
        return res;
    }

    private static void setUCypherDEV(ResourceBundle res, String pname) {
        if (res.containsKey(pname)) {
            String str = res.getString(pname);
            if ((str != null) && !"".equals(str)) {
                udev.setProperty(pname, str);
            }
        }
    }

}
