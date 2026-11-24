package org.example.netty.uds;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.kqueue.KQueue;
import io.netty.channel.kqueue.KQueueDomainSocketChannel;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.util.CharsetUtil;

import java.util.Scanner;

public class NettyUdsClient {

    private static final String SOCKET_PATH = "/tmp/netty-uds-demo.sock";

    public static void main(String[] args) throws Exception {
        EventLoopGroup group;
        Class<? extends Channel> clientChannelClass;

        if (Epoll.isAvailable()) {
            group = new EpollEventLoopGroup();
            clientChannelClass = EpollDomainSocketChannel.class;
            System.out.println("[NettyUdsClient] 使用 Epoll 传输");
        } else if (KQueue.isAvailable()) {
            group = new KQueueEventLoopGroup();
            clientChannelClass = KQueueDomainSocketChannel.class;
            System.out.println("[NettyUdsClient] 使用 KQueue 传输");
        } else {
            System.err.println("[NettyUdsClient] Epoll 和 KQueue 均不可用，UDS 需要 Linux 或 macOS");
            return;
        }

        try {
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(group)
                    .channel(clientChannelClass)
                    .handler(new ChannelInitializer<>() {
                        @Override
                        protected void initChannel(io.netty.channel.Channel ch) {
                            ChannelPipeline pipeline = ch.pipeline();
                            pipeline.addLast(new StringDecoder(CharsetUtil.UTF_8));
                            pipeline.addLast(new StringEncoder(CharsetUtil.UTF_8));
                            pipeline.addLast(new UdsClientHandler());
                        }
                    });

            ChannelFuture future = bootstrap.connect(new DomainSocketAddress(SOCKET_PATH)).sync();
            Channel channel = future.channel();
            System.out.println("[NettyUdsClient] 已连接到 UDS: " + SOCKET_PATH);

            Scanner scanner = new Scanner(System.in);
            System.out.println("[NettyUdsClient] 输入消息（输入 bye 退出）:");

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                channel.writeAndFlush(line);
                if ("bye".equalsIgnoreCase(line)) {
                    break;
                }
            }

            channel.close().sync();
        } finally {
            group.shutdownGracefully();
        }
    }
}
