package org.example.netty.uds;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

public class UdsServerHandler extends SimpleChannelInboundHandler<String> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) {
        System.out.println("[UdsServerHandler] 收到: " + msg);

        if ("bye".equalsIgnoreCase(msg.trim())) {
            ctx.writeAndFlush("再见！");
            ctx.close();
            return;
        }

        ctx.writeAndFlush("Netty UDS 服务器回复: [" + msg + "]");
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        System.out.println("[UdsServerHandler] 客户端连接: " + ctx.channel().remoteAddress());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        System.out.println("[UdsServerHandler] 客户端断开");
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}
