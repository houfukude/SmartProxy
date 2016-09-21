package me.smartproxy.core;

import java.net.InetSocketAddress;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import me.smartproxy.tunnel.Config;
import me.smartproxy.tunnel.RawTunnel;
import me.smartproxy.tunnel.Tunnel;
import me.smartproxy.tunnel.httpconnect.HttpConnectConfig;
import me.smartproxy.tunnel.httpconnect.HttpConnectTunnel;
import me.smartproxy.tunnel.shadowsocks.ShadowsocksConfig;
import me.smartproxy.tunnel.shadowsocks.ShadowsocksTunnel;

/**
 * 创建隧道的工厂
 */
public class TunnelFactory {

	/**
	 * 将SocketChannel和Selector包装成隧道，主要用于本地的隧道（Local Tunnel）
	 * @param channel
	 * @param selector
     * @return
     */
	public static Tunnel wrap(SocketChannel channel,Selector selector){
		return new RawTunnel(channel, selector);
	}


	/**
	 * 根据配置创建隧道，主要用户创建远程的隧道
	 * @param destAddress 隧道最终要连接的远程地址
	 * @param selector 代理服务器的selector
	 * @return
	 * @throws Exception
     */
	public static Tunnel createTunnelByConfig(InetSocketAddress destAddress,Selector selector) throws Exception {
		if(destAddress.isUnresolved()){
			Config config=ProxyConfig.Instance.getDefaultTunnelConfig(destAddress);
			if(config instanceof HttpConnectConfig){
				return new HttpConnectTunnel((HttpConnectConfig)config,selector);
			}else if(config instanceof ShadowsocksConfig){
				return new ShadowsocksTunnel((ShadowsocksConfig)config,selector); 
			} 
			throw new Exception("The config is unknow.");
		}else {
			return new RawTunnel(destAddress, selector);
		}
	}

}
