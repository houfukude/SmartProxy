package me.smartproxy.tunnel;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

/**
 * 无需做任何额外的数据处理的隧道,主要用于本地连接
 */
public class RawTunnel extends Tunnel {

	public RawTunnel(InetSocketAddress serverAddress,Selector selector) throws Exception{
		super(serverAddress,selector);
	}
	
	public RawTunnel(SocketChannel innerChannel, Selector selector) {
		super(innerChannel, selector);
	}

	@Override
	protected void onConnected(ByteBuffer buffer) throws Exception {
		onTunnelEstablished();
	}

	@Override
	protected void beforeSend(ByteBuffer buffer) throws Exception {
		//无需处理
	}

	@Override
	protected void afterReceived(ByteBuffer buffer) throws Exception {
		//无需处理
	}

	@Override
	protected boolean isTunnelEstablished() {
		return true;
	}

	@Override
	protected void onDispose() {
		//无需处理
	}

}
