package me.smartproxy.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import me.smartproxy.tcpip.CommonMethods;
import me.smartproxy.tunnel.Tunnel;

/**
 * TCP代理服务器，用来转发VPN的数据包到Tunnel
 */
public class TcpProxyServer {

	final static Logger logger = Logger.getLogger(TcpProxyServer.class.getName());

	static int THREAD_NUM = 5;

	public boolean Stopped;
	public short Port;

	Selector[] selectors;

	ServerSocketChannel m_ServerSocketChannel;
	ExecutorService executorService;

	//构造函数，初始化监听，使用了ServerSocketChannel和Selector机制
	public TcpProxyServer(int port) throws IOException {

		selectors = new Selector[1];
		for (int i = selectors.length - 1; i != -1; --i){
			selectors[i] = Selector.open();
		}

		m_ServerSocketChannel = ServerSocketChannel.open();
		m_ServerSocketChannel.configureBlocking(false);
		m_ServerSocketChannel.socket().bind(new InetSocketAddress(port));
		m_ServerSocketChannel.register(selectors[0], SelectionKey.OP_ACCEPT);
		this.Port=(short) m_ServerSocketChannel.socket().getLocalPort();

		logger.info(String.format("AsyncTcpServer listen on %d success.\n", this.Port&0xFFFF));
	}

	//启动方法，其实是启动线程进行selector轮询
	public void start(){
		executorService = Executors.newFixedThreadPool(THREAD_NUM);
		for (Selector selector : selectors) {
			executorService.execute(new SelectorTask(selector));
		}
	}

	//停止代理服务器
	public void stop(){
		this.Stopped= true;

		if(selectors != null){
			for (Selector selector : selectors) {
				try {
					selector.close();
				} catch (Exception e) {
					logger.log(Level.SEVERE, e.getMessage(), e);
				}
			}
		}
			
		if(m_ServerSocketChannel!=null){
			try {
				m_ServerSocketChannel.close();
				m_ServerSocketChannel=null;
			} catch (Exception e) {
				logger.log(Level.SEVERE, e.getMessage(), e);
			}
		}

		executorService.shutdownNow();
	}


	/**
	 * 根据端口获取对应的selector
	 * @param port
	 * @return
     */
	private Selector getSelector(int port){
		return selectors[port % selectors.length];
	}

	/**
	 * 获取从VPN过来的连接的真实连接地址，通过NAT表进行查询
	 * @param localChannel
	 * @return
     */
	private InetSocketAddress getDestAddress(SocketChannel localChannel){
		short portKey=(short)localChannel.socket().getPort();
		NatSession session =NatSessionManager.getSession(portKey);
		if (session != null) {
			if(ProxyConfig.Instance.needProxy(session.RemoteHost, session.RemoteIP)){
				if(ProxyConfig.IS_DEBUG)
					System.out.printf("%d/%d:[PROXY] %s=>%s:%d\n",NatSessionManager.getSessionCount(), Tunnel.SessionCount,session.RemoteHost,CommonMethods.ipIntToString(session.RemoteIP),session.RemotePort&0xFFFF);
				return InetSocketAddress.createUnresolved(session.RemoteHost, session.RemotePort&0xFFFF);
			}else {
			    return new InetSocketAddress(localChannel.socket().getInetAddress(),session.RemotePort&0xFFFF);
			}
		}
		return null;
	}

	/**
	 * 建立连接
	 *
	 * @param key
	 */
	private void onAccepted(SelectionKey key) {
		Tunnel localTunnel = null;
		try {
			//在LocalVpnService里面，已经将发出去的包进行了修改，目标IP和端口为本代理服务器，源IP和端口即为发起网络连接的本地进程
			//所以本地隧道相当于直接与进程打通，远程隧道的数据直接发送到本地隧道即可到达对应的进程

			SocketChannel localChannel = m_ServerSocketChannel.accept(); //来自本地客户端的连接

			Selector selector = getSelector(localChannel.socket().getPort());
			localTunnel = TunnelFactory.wrap(localChannel, selector);

			//根据本地连接，获取要连接的远程地址
			InetSocketAddress destAddress = getDestAddress(localChannel);
			if (destAddress != null) {

				//创建隧道连接，这里将本地的连接也封装成隧道，然后根据本地连接要连接的远程地址，创建一个远程的连接，并且将两个连接关联起来（相当于将两个隧道接在一起）
				Tunnel remoteTunnel = TunnelFactory.createTunnelByConfig(destAddress, selector);
				remoteTunnel.setBrotherTunnel(localTunnel);//关联兄弟
				localTunnel.setBrotherTunnel(remoteTunnel);//关联兄弟
				remoteTunnel.connect(destAddress);//开始连接到远程VPN(代理)服务器
			} else {
				LocalVpnService.Instance.writeLog("Error: socket(%s:%d) target host is null.", localChannel.socket().getInetAddress().toString(), localChannel.socket().getPort());
				localTunnel.dispose();
			}
		} catch (Exception e) {
			logger.log(Level.SEVERE, e.getMessage(), e);

			LocalVpnService.Instance.writeLog("Error: remote socket create failed: %s", e.toString());
			if (localTunnel != null) {
				localTunnel.dispose();
			}
		}
	}


	/**
	 * 执行Selector逻辑的多线程处理, 实际上所有的通信处理都在这里面进行
	 */
	class SelectorTask implements Runnable{

		Selector selector;
		public SelectorTask(Selector selector){
			this.selector = selector;
		}

		//线程内部，不停地对selector进行select操作
		@Override
		public void run() {
			try {
				while (true) {
					selector.select();
					Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
					while (keyIterator.hasNext()) {
						SelectionKey key = keyIterator.next();
						if (key.isValid()) {
							try {
								if (key.isReadable()) {//本地或者远程隧道可写
									((Tunnel)key.attachment()).onReadable(key);
								}
								else if(key.isWritable()){//本地或者远程隧道可写
									((Tunnel)key.attachment()).onWritable(key);
								}
								else if (key.isConnectable()) { //远程隧道连接成功，此时的Tunnel为远程隧道。本地隧道不会有connect事件
									((Tunnel)key.attachment()).onConnectable();
								}
								else  if (key.isAcceptable()) { //本地Tcp代理服务器收到新的连接
									onAccepted(key);
								}
							} catch (Exception e) {
								logger.log(Level.SEVERE, e.getMessage(), e);
							}
						}
						keyIterator.remove();
					}
				}
			} catch (Exception e) {
				logger.log(Level.SEVERE, e.getMessage(), e);
			}finally{
				stop();
				logger.info("TcpServer thread exited.");
			}
		}
	}

}
