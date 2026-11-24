package org.example.netty.uds;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.ServerChannel;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollServerDomainSocketChannel;
import io.netty.channel.kqueue.KQueue;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.kqueue.KQueueServerDomainSocketChannel;
import io.netty.channel.unix.DomainSocketAddress;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.util.CharsetUtil;

import java.io.File;

public class NettyUdsServer {

    private static final String SOCKET_PATH = "/tmp/netty-uds-demo.sock";

    public static void main(String[] args) throws Exception {
        new File(SOCKET_PATH).delete();

        EventLoopGroup bossGroup;
        EventLoopGroup workerGroup;
        Class<? extends ServerChannel> serverChannelClass;

        if (Epoll.isAvailable()) {
            bossGroup = new EpollEventLoopGroup(1);
            workerGroup = new EpollEventLoopGroup();
            serverChannelClass = EpollServerDomainSocketChannel.class;
            System.out.println("[NettyUdsServer] 使用 Epoll 传输");
        } else if (KQueue.isAvailable()) {
            bossGroup = new KQueueEventLoopGroup(1);
            workerGroup = new KQueueEventLoopGroup();
            serverChannelClass = KQueueServerDomainSocketChannel.class;
            System.out.println("[NettyUdsServer] 使用 KQueue 传输");
        } else {
            System.err.println("[NettyUdsServer] Epoll 和 KQueue 均不可用，UDS 需要 Linux 或 macOS");
            return;
        }

        try {
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(bossGroup, workerGroup)
                    .channel(serverChannelClass)
                    .childHandler(new ChannelInitializer<>() {
                        @Override
                        protected void initChannel(io.netty.channel.Channel ch) {
                            ChannelPipeline pipeline = ch.pipeline();
                            pipeline.addLast(new StringDecoder(CharsetUtil.UTF_8));
                            pipeline.addLast(new StringEncoder(CharsetUtil.UTF_8));
                            pipeline.addLast(new UdsServerHandler());
                        }
                    });

            ChannelFuture future = bootstrap.bind(new DomainSocketAddress(SOCKET_PATH)).sync();
            System.out.println("[NettyUdsServer] 监听中: " + SOCKET_PATH);

            future.channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
            new File(SOCKET_PATH).delete();
        }
    }
}
