package cn.com.zxy.springboot;

import cn.com.infosec.ucypher.spec.agent.UCypherProvider;
import org.apache.catalina.connector.Connector;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.Security;
import java.util.Objects;

@SpringBootApplication
public class SpringbootApplication {

    // static{
    //     String configFile = "D:\\infosec_project\\java_agent_fuzai\\ucypher-test\\src\\main\\resources\\ucypheragent.properties";
    //     try {
    //         UCypherProvider provider = new UCypherProvider(configFile);
    //         Security.addProvider(provider);
    //     } catch (Exception e) {
    //         throw new RuntimeException(e);
    //     }
    // }


    public static void main(String[] args) {
        SpringApplication.run(SpringbootApplication.class, args);
    }

    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        tomcat.setPort(8443); // 默认 HTTPS 端口
        tomcat.addAdditionalTomcatConnectors(createRedirectConnector(), createHTTPConnector());
        return tomcat;
    }

    private Connector createHTTPConnector() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setSecure(false);
        connector.setPort(8081);
        return connector;
    }

    private Connector createRedirectConnector() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setSecure(false);
        connector.setPort(8082);       // 访问入口
        connector.setRedirectPort(8443); // 自动跳转到 HTTPS
        return connector;
    }

}
