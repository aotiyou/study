package org.example.pool;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.Socket;

/**
 * @author aotiyou
 * @since 2025/9/9
 */
@Data
@Slf4j
public class SocketConnection {

    private Socket socket;
    private InputStream reader;
    private PrintStream out;
    private int id; // 对象标识

    public SocketConnection() throws IOException {
        this.socket = new Socket("127.0.0.1", 9999);
        this.reader = socket.getInputStream();
        this.out = new PrintStream(socket.getOutputStream());
        this.id = (int) Math.random() * Integer.MAX_VALUE;
    }

    public void report(){
        System.out.println("socketConnection ID IS:"+this.id);
    }

    private void login(PrintStream out,InputStream reader){
        log.info("登录成功！");
    }
    public void reLogin() throws Exception {
        if(this.socket.isConnected() || !this.socket.isClosed()){
            this.socket.close();
        }
        if(this.reader != null){
            this.reader.close();
        }
        if(this.out != null){
            this.out.close();
        }
        //重新连接，登录
        log.info("开始重新登录！");
        this.socket = new Socket("127.0.0.1",9999);
        this.reader = socket.getInputStream();
        this.out = new PrintStream(socket.getOutputStream());
        login(this.out,this.reader);
    }

}
