package org.example.pool;

import org.apache.commons.pool2.impl.GenericObjectPool;

public class ConnectionPool extends GenericObjectPool<SocketConnection> {

    public ConnectionPool() {
        super(new SocketConnectionFacory2(), new ConnectionPoolConfig());
    }

    public ConnectionPool(ConnectionPoolConfig connPoolConfig) {
        super(new SocketConnectionFacory2(), connPoolConfig);
    }
}
