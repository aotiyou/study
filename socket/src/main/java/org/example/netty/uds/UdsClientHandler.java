package org.example.netty.uds;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

public class UdsClientHandler extends SimpleChannelInboundHandler<String> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) {
        System.out.println("[UdsClientHandler] " + msg);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        System.out.println("[UdsClientHandler] 连接建立成功");
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        System.out.println("[UdsClientHandler] 连接断开");
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}
