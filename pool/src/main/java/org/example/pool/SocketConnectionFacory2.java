package org.example.pool;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;

import java.net.Socket;

@Slf4j
public class SocketConnectionFacory2 extends BasePooledObjectFactory<SocketConnection> {



    @Override
    public SocketConnection create() throws Exception {
        SocketConnection connection = new SocketConnection();
        log.info("创建socket..."+connection);
        return connection;
    }

    @Override
    public PooledObject<SocketConnection> wrap(SocketConnection socketConnection) {
        return new DefaultPooledObject<SocketConnection>(socketConnection);
    }

    /**
     * 借对象之前判断对象是否正常可用，如果连接断开则重新连接并登陆
     * @param p
     * @throws Exception
     */
    @Override
    public void activateObject(PooledObject<SocketConnection> p) throws Exception {
        SocketConnection connection = p.getObject();
        log.info("调用激活方法"+connection);
        if(connection != null){
            try {
                log.info("发送hello信息！");
//                String response = connection.sendCmd(connection.getOut(),connection.getReader(),"hello",true);
                connection.reLogin();
//                log.info("hello==>response："+response);
            }catch (Exception e){
                log.error("connection对象异常！{},开始重新连接登录！",e.getMessage());
                connection.reLogin();
            }

        }
    }

    /**
     * 钝化对象：还
     * @param p
     * @throws Exception
     */
    @Override
    public void passivateObject(PooledObject<SocketConnection> p) throws Exception {
        super.passivateObject(p);
    }

    @Override
    public boolean validateObject(PooledObject<SocketConnection> p) {
        System.out.println("开始验证！！！");
        SocketConnection socketConnection = p.getObject();
        if(socketConnection.getSocket() != null){
            Socket socket = socketConnection.getSocket();
            if(socket.isClosed()){
                log.info("socket is Closed！！");
                return false;
            }
            if(!socket.isConnected()){
                log.info("socket is not connected！！！");
                return false;
            }
        }
        return false;
    }
}
