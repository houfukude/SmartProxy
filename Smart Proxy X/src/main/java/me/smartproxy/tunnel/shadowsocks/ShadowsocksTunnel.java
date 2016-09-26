package me.smartproxy.tunnel.shadowsocks;

import java.nio.ByteBuffer;
import java.nio.channels.Selector;

import me.smartproxy.tunnel.Tunnel;

public class ShadowsocksTunnel extends Tunnel {

	private ShadowsocksEncryptor m_Encryptor;
	private ShadowsocksConfig m_Config;
	private boolean m_TunnelEstablished;

	private boolean isFirstReceive = true;

	public ShadowsocksTunnel(ShadowsocksConfig config,Selector selector) throws Exception {
		super(config.ServerAddress, selector);
		if (config.Encryptor == null) {
			throw new Exception("Error: The Encryptor for ShadowsocksTunnel is null.");
		}
		m_Config = config;

		//create a new encryptor each time
		m_Encryptor = EncryptorFactory.createEncryptorByConfig(config);
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
		byte[] iv = m_Encryptor.getEncryptIV();
		if (iv != null && iv.length > 0){
			byte[] data = new byte[buffer.remaining()];
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

		m_TunnelEstablished = true;
		onTunnelEstablished();
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
			//第一次接收设置IV
			if (m_Encryptor.getIVLength() > 0 && isFirstReceive) {
				synchronized (this) {
					if (isFirstReceive) { //set IV
						byte[] decryptIV = new byte[m_Encryptor.getIVLength()];
						buffer.get(decryptIV);
						m_Encryptor.initDecryptor(decryptIV);

						isFirstReceive = false;
					}
				}
			}

			m_Encryptor.decrypt(buffer);

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
