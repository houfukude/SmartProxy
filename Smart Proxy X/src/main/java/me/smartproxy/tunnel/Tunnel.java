package me.smartproxy.tunnel;

import android.annotation.SuppressLint;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import me.smartproxy.core.LocalVpnService;
import me.smartproxy.core.ProxyConfig;


/**
 * Tunnel类
 */
public abstract class Tunnel {

	public static long SessionCount;									//当前连接中的Tunnel计数器


	/**
	 * 与远程VPN（代理）服务器连接成功，可以进行握手等操作
	 * @param buffer
	 * @throws Exception
     */
    protected abstract void onConnected(ByteBuffer buffer) throws Exception;

	/**
	 * 隧道是否已建立
	 * @return
     */
    protected abstract boolean isTunnelEstablished();

	/**
	 * 在发送数据之前，对要发送的数据进行处理
	 * @param buffer 待发送的数据
	 * @throws Exception
     */
    protected abstract void beforeSend(ByteBuffer buffer) throws Exception;


	/**
	 * 接收到数据之后，对接到到的数据进行处理
	 * @param buffer 隧道接收到的数据
	 * @throws Exception
     */
	protected abstract void afterReceived(ByteBuffer buffer) throws Exception;


	/**
	 * 隧道关闭后的回调
	 */
	protected abstract void onDispose();


    
	private SocketChannel m_InnerChannel;			//连接到远程VPN（代理）服务器的连接

	protected final static ByteBuffer GL_BUFFER = ByteBuffer.allocate(20000);		//读数据的Buffer

	private ByteBuffer m_SendRemainBuffer;			//待发送数据

	private Selector m_Selector;					//使用的Selector，与Tcp代理服务器使用的是同一个Selector，轮询在TcpProxyServer里面
	private Tunnel m_BrotherTunnel;					//相关联的兄弟Tunnel
	private boolean m_Disposed;						//是否已经废弃
    private InetSocketAddress m_ServerEP;			//远程VPN(代理)服务器的地址
    protected InetSocketAddress m_DestAddress;		//要连接的目标服务器的地址


	/**
	 * 根据已建立的连接和Selector创建隧道<br/>
	 * 主要用于本地TCP服务器到本地进程的隧道，此时innerChannel对应的连接已建立，不可再调用connect方法
	 * @param innerChannel
	 * @param selector
     */
	public Tunnel(SocketChannel innerChannel,Selector selector){
		this.m_InnerChannel=innerChannel;
		this.m_Selector=selector;
		SessionCount++;
	}

	/**
	 * 根据远程VPN（代理）服务器创建新的隧道，并未创建真正的连接
	 * @param serverAddress
	 * @param selector
	 * @throws IOException
     */
	public Tunnel(InetSocketAddress serverAddress,Selector selector) throws IOException{
		SocketChannel innerChannel=SocketChannel.open();
		innerChannel.configureBlocking(false);
		this.m_InnerChannel=innerChannel;
		this.m_Selector=selector;
		this.m_ServerEP=serverAddress;
		SessionCount++;
	}

	/**
	 * 设置关联的隧道，相当于两个隧道连接起来
	 * @param brotherTunnel
     */
	public void setBrotherTunnel(Tunnel brotherTunnel){
		m_BrotherTunnel=brotherTunnel;
	}


	/**
	 * 建立一个连接到目标地址的隧道链接<br/>
	 *
	 * @param destAddress
	 * @throws Exception
     */
	public void connect(InetSocketAddress destAddress) throws Exception{
		//如果已建立，则直接返回
		if (m_InnerChannel.isConnected()){
			return;
		}

		if(LocalVpnService.Instance.protect(m_InnerChannel.socket())){//保护socket不走vpn
			m_DestAddress=destAddress;
			m_InnerChannel.register(m_Selector, SelectionKey.OP_CONNECT,this);//注册连接事件
			m_InnerChannel.connect(m_ServerEP);//连接目标
		}else {
			throw new Exception("VPN protect socket failed.");
		}
	}

	/**
	 * 注册接收数据的事件,准备读取数据
	 * @throws Exception
     */
	protected void beginReceive() throws Exception{
		if(m_InnerChannel.isBlocking()){
			m_InnerChannel.configureBlocking(false);
		}
		m_InnerChannel.register(m_Selector, SelectionKey.OP_READ,this);//注册读事件
	}


	/**
	 * 往隧道写入数据,先尝试直接写入,如果失败,则将数据放到待发送数据中,等待可发送的时候再进行处理
	 * @param buffer
	 * @param copyRemainData
	 * @return
	 * @throws Exception
     */
	protected boolean write(ByteBuffer buffer,boolean copyRemainData) throws Exception {
		int bytesSent;
    	while (buffer.hasRemaining()) {
			bytesSent=m_InnerChannel.write(buffer);
			if(bytesSent==0){
				break;//不能再发送了，终止循环
			}
		}
    	
    	if(buffer.hasRemaining()){//数据没有发送完毕
    		if(copyRemainData){//拷贝剩余数据，然后侦听写入事件，待可写入时写入。
    			//拷贝剩余数据
    			if(m_SendRemainBuffer==null){
    				m_SendRemainBuffer=ByteBuffer.allocate(buffer.capacity());
    			}
    			m_SendRemainBuffer.clear();
        		m_SendRemainBuffer.put(buffer);
    			m_SendRemainBuffer.flip();
    			m_InnerChannel.register(m_Selector,SelectionKey.OP_WRITE, this);//注册写事件
    		}
			return false;
    	}
    	else {//发送完毕了
    		return true;
		}
	}

	/**
	 * 隧道建立成功之后，子类必须调用此方法，通知隧道开始接收数据
	 * @throws Exception
     */
    protected void onTunnelEstablished() throws Exception{
		this.beginReceive();//开始接收数据
		m_BrotherTunnel.beginReceive();//兄弟也开始收数据吧

		if (m_ServerEP != null && m_DestAddress != null) {
			System.out.println(String.format("new Tunnel established: %s:%d=>%s:%d", m_ServerEP.getHostName(), m_ServerEP.getPort(), m_DestAddress.getHostName(), m_DestAddress.getPort()));
		}
    }

    @SuppressLint("DefaultLocale")
	public void onConnectable(){
    	try {
        	if(m_InnerChannel.finishConnect()){//连接成功
        		onConnected(GL_BUFFER);//通知子类TCP已连接，子类可以根据协议实现握手等。
        	}else {//连接失败
        		LocalVpnService.Instance.writeLog("Error: connect to %s failed.",m_ServerEP);
				this.dispose();
			}
		} catch (Exception e) {
			LocalVpnService.Instance.writeLog("Error: connect to %s exception: %s", m_ServerEP,e);
			this.dispose();
		}
    }


	/**
	 * 隧道读数据,　由Tcp代理服务器中的Selector轮询调用<br/>
	 * 读到数据之后,首先调用afterReceived方法进行加解密处理,然后后在将数据交给兄弟隧道进行处理
	 * @param key
	 */
	public void onReadable(SelectionKey key) {
		try {
			ByteBuffer buffer = GL_BUFFER;
			buffer.clear();
			int bytesRead = m_InnerChannel.read(buffer);
			if (bytesRead > 0) {
				buffer.flip();
				afterReceived(buffer);//先让子类处理，例如解密数据。
				if (isTunnelEstablished() && buffer.hasRemaining()) {//将读到的数据，转发给兄弟。
					m_BrotherTunnel.beforeSend(buffer);//发送之前，先让子类处理，例如做加密等。
					if (!m_BrotherTunnel.write(buffer, true)) {
						key.cancel();//兄弟吃不消，就取消读取事件(兄弟写完之后,会再次注册读的事件)。
						if (ProxyConfig.IS_DEBUG)
							System.out.printf("%s can not read more.\n", m_ServerEP);
					}
				}
			} else if (bytesRead < 0) {
				this.dispose();//连接已关闭，释放资源。
			}
		} catch (Exception e) {
			e.printStackTrace();
			this.dispose();
		}
	}

	/**
	 * 隧道发送数据,　由Tcp代理服务器中的Selector轮询调用<br/>
	 * 写之前,先调用beforeSend方法,对数据进行处理。写完之后通知兄弟隧道进行接收
	 * @param key
     */
	public void onWritable(SelectionKey key){
		try {
			this.beforeSend(m_SendRemainBuffer);//发送之前，先让子类处理，例如做加密等。
			if(this.write(m_SendRemainBuffer, false)) {//如果剩余数据已经发送完毕
				key.cancel();//取消写事件。
				if(isTunnelEstablished()){
					m_BrotherTunnel.beginReceive();//这边数据发送完毕，通知兄弟可以收数据了。
				}else {
					this.beginReceive();//开始接收代理服务器响应数据
				}
			}else {
				//TODO 有没有一次写不完的情况?
				//貌似比较ByteBuffer比较只能,如果一次未写完,则不取消写入的SelectionKey,会等待下次继续写
			}
		} catch (Exception e) {
			this.dispose();
		}
	}

	/**
	 * 销毁隧道
	 */
	public void dispose(){
		disposeInternal(true);
	}

	/**
	 * 执行销毁隧道的操作
	 * @param disposeBrother
     */
	void disposeInternal(boolean disposeBrother) {
		if(m_Disposed){
			return;
		}
		else {
			try {
				m_InnerChannel.close();
			} catch (Exception e) {
			}
			
			if(m_BrotherTunnel!=null&&disposeBrother){
				m_BrotherTunnel.disposeInternal(false);//把兄弟的资源也释放了。
			}

			m_InnerChannel=null;
		    m_SendRemainBuffer=null;
			m_Selector=null;
			m_BrotherTunnel=null;
			m_Disposed=true;
			SessionCount--;
			
			onDispose();
		}
	}
}
