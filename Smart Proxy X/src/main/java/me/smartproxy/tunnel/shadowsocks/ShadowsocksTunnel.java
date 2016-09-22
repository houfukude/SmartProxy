package me.smartproxy.tunnel.shadowsocks;

import java.nio.ByteBuffer;
import java.nio.channels.Selector;

import me.smartproxy.tunnel.IEncryptor;
import me.smartproxy.tunnel.Tunnel;

public class ShadowsocksTunnel extends Tunnel {

	private AbstractEncryptor m_Encryptor;
	private ShadowsocksConfig m_Config;
	private boolean m_TunnelEstablished;
	
	public ShadowsocksTunnel(ShadowsocksConfig config,Selector selector) throws Exception {
		super(config.ServerAddress, selector);
		if (config.Encryptor == null) {
			throw new Exception("Error: The Encryptor for ShadowsocksTunnel is null.");
		}
		m_Config = config;
		m_Encryptor = (AbstractEncryptor) config.Encryptor;
	}

	@Override
	protected void onConnected(ByteBuffer buffer) throws Exception {
		
		//构造socks5请求（跳过前3个字节）
		buffer.clear();
		buffer.put((byte)0x03);//domain
		byte[] domainBytes=m_DestAddress.getHostName().getBytes();
		buffer.put((byte)domainBytes.length);//domain length;
		buffer.put(domainBytes);
		buffer.putShort((short)m_DestAddress.getPort());
		buffer.flip();

		//加密请求数据
		m_Encryptor.encrypt(buffer);

		//如果iv不为空,则将iv放在前面
		byte[] iv = m_Encryptor.getIV();
		if (iv != null && iv.length > 0){
			byte[] data = new byte[buffer.limit()];
			buffer.get(data);

			//将iv放在头部
			buffer.clear();
			buffer.put(iv);
			buffer.put(data);
			buffer.flip();
		}

        if(write(buffer, true)){
			this.beginReceive();
		}
	}

	@Override
	protected boolean isTunnelEstablished() {
		return m_TunnelEstablished;
	}

	@Override
	protected void beforeSend(ByteBuffer buffer) throws Exception {
		 m_Encryptor.encrypt(buffer);
	}

	@Override
	protected void afterReceived(ByteBuffer buffer) throws Exception {
		try {
			m_Encryptor.decrypt(buffer);

			if (!m_TunnelEstablished){ //第一次解密成功,才表示真正建立起了隧道
				m_TunnelEstablished = true;
				onTunnelEstablished();
			}
		}catch (Exception e){
			throw e;
		}
	}

	@Override
	protected void onDispose() {
		 m_Config=null;
		 m_Encryptor=null;
	}

}
