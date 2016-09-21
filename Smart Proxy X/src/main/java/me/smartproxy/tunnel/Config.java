package me.smartproxy.tunnel;

import java.net.InetSocketAddress;
import java.nio.channels.Selector;

/**
 * 连接到远程VPN(代理)服务器的配置
 */
public abstract class Config {
	public InetSocketAddress ServerAddress;
	public IEncryptor Encryptor;
}
