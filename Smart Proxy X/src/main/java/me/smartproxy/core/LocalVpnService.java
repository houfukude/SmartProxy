package me.smartproxy.core;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import me.smartproxy.core.ProxyConfig.IPAddress;
import me.smartproxy.dns.DnsPacket;
import me.smartproxy.tcpip.CommonMethods;
import me.smartproxy.tcpip.IPHeader;
import me.smartproxy.tcpip.TCPHeader;
import me.smartproxy.tcpip.UDPHeader;
import me.smartproxy.ui.MainActivity;
import me.smartproxy.R;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.util.Log;

public class LocalVpnService extends VpnService implements Runnable {

	private static final String TAG = LocalVpnService.class.getName();


	public static LocalVpnService Instance;
    public static String ConfigUrl;
	public static boolean IsRunning = false;

	private static int ID;
	private static int LOCAL_IP;
	private static ConcurrentHashMap<onStatusChangedListener, Object> m_OnStatusChangedListeners=new ConcurrentHashMap<onStatusChangedListener, Object>();

	private Thread m_VPNThread;
	private ParcelFileDescriptor m_VPNInterface;
	private TcpProxyServer m_TcpProxyServer;
	private DnsProxy m_DnsProxy;
	private FileOutputStream m_VPNOutputStream;
	
	private byte[] m_Packet;
	private IPHeader m_IPHeader;
	private TCPHeader m_TCPHeader;
	private UDPHeader m_UDPHeader;
	private ByteBuffer m_DNSBuffer;
	private Handler m_Handler;
	private long m_SentBytes;
	private long m_ReceivedBytes;
	
	public LocalVpnService() {
		ID++;
		m_Handler=new Handler();
		m_Packet = new byte[20000];
		m_IPHeader = new IPHeader(m_Packet, 0);
		m_TCPHeader=new TCPHeader(m_Packet, 20);
		m_UDPHeader=new UDPHeader(m_Packet, 20);
		m_DNSBuffer=((ByteBuffer)ByteBuffer.wrap(m_Packet).position(28)).slice();
		Instance=this; 
		
		System.out.printf("New VPNService(%d)\n",ID);
	}

	@Override
	public void onCreate() {
		System.out.printf("VPNService(%s) created.\n", ID);
		// Start a new session by creating a new thread.
		m_VPNThread = new Thread(this, "VPNServiceThread");
		m_VPNThread.start();
		super.onCreate();
	}
	
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		IsRunning=true;
		return super.onStartCommand(intent, flags, startId);
	}
	
	public interface onStatusChangedListener {
		public void onStatusChanged(String status,Boolean isRunning);
		public void onLogReceived(String logString);
	}

	public static void addOnStatusChangedListener(onStatusChangedListener listener) {
		if (!m_OnStatusChangedListeners.containsKey(listener)) {
			m_OnStatusChangedListeners.put(listener, 1);
		}
	}

	public static void removeOnStatusChangedListener(onStatusChangedListener listener) {
		if (m_OnStatusChangedListeners.containsKey(listener)) {
			m_OnStatusChangedListeners.remove(listener);
		}
	}
	
	private void onStatusChanged(final String status, final boolean isRunning) {
		m_Handler.post(new Runnable() {
			@Override
			public void run() {
				for (Map.Entry<onStatusChangedListener, Object> entry : m_OnStatusChangedListeners.entrySet()) {
				    entry.getKey().onStatusChanged(status,isRunning);
				}
			}
		});
	}
	
	public void writeLog(final String format,Object... args) {
		final String logString=String.format(format, args);
		m_Handler.post(new Runnable() {
			@Override
			public void run() {
				for (Map.Entry<onStatusChangedListener, Object> entry : m_OnStatusChangedListeners.entrySet()) {
				    entry.getKey().onLogReceived(logString);
				}
			}
		});
	}
 
	public void sendUDPPacket(IPHeader ipHeader, UDPHeader udpHeader) {
		try {
			CommonMethods.ComputeUDPChecksum(ipHeader, udpHeader);
			this.m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, ipHeader.getTotalLength());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	String getAppInstallID(){
		 SharedPreferences preferences = getSharedPreferences("SmartProxy", MODE_PRIVATE); 
		 String appInstallID=preferences.getString("AppInstallID", null);
		 if(appInstallID==null||appInstallID.isEmpty()){
			 appInstallID=UUID.randomUUID().toString();
			 Editor editor = preferences.edit(); 
			 editor.putString("AppInstallID", appInstallID);
			 editor.commit();
		 }
		 return appInstallID;
	}
	
	String getVersionName()  {
		 try {
	           PackageManager packageManager = getPackageManager();
	           // getPackageName()是你当前类的包名，0代表是获取版本信息
	           PackageInfo packInfo = packageManager.getPackageInfo(getPackageName(),0);
	           String version = packInfo.versionName;
	           return version;
		} catch (Exception e) {
			return "0.0";
		}   
	 }
 
	@Override
	public synchronized void run() {
		try {
			System.out.printf("VPNService(%s) work thread is runing...\n", ID);
 
			ProxyConfig.AppInstallID=getAppInstallID();//获取安装ID
			ProxyConfig.AppVersion=getVersionName();//获取版本号
			System.out.printf("AppInstallID: %s\n", ProxyConfig.AppInstallID);
			writeLog("Android version: %s", Build.VERSION.RELEASE);
			writeLog("App version: %s", ProxyConfig.AppVersion);
			
			
			ChinaIpMaskManager.loadFromFile(getResources().openRawResource(R.raw.ipmask));//加载中国的IP段，用于IP分流。
			waitUntilPreapred();//检查是否准备完毕。

			//启动进行转发的TCP Server
			m_TcpProxyServer = new TcpProxyServer(0);
			m_TcpProxyServer.start();
			writeLog("LocalTcpServer started.");

			//启动DNS 代理服务器，目前TCP代理只能处理TCP包，对于DNS请求，需要单独代理
			m_DnsProxy = new DnsProxy();
			m_DnsProxy.start();
			writeLog("LocalDnsProxy started.");

			while (true) {
				if (IsRunning) {
					//加载配置文件
					writeLog("Load config from %s ...", ConfigUrl);
					try {
						ProxyConfig.Instance.loadFromUrl(ConfigUrl);
						if(ProxyConfig.Instance.getDefaultProxy()==null){
							throw new Exception("Invalid config file.");
						}
						writeLog("PROXY %s", ProxyConfig.Instance.getDefaultProxy());
					} catch (Exception e) {
						String errString=e.getMessage();
						if(errString==null||errString.isEmpty()){
							errString=e.toString();
						}
						
						IsRunning=false;
						onStatusChanged(errString, false);
						continue;
					}
					
					writeLog("Load config success.");
					String welcomeInfoString=ProxyConfig.Instance.getWelcomeInfo();
					if(welcomeInfoString!=null&&!welcomeInfoString.isEmpty()){
						writeLog("%s", ProxyConfig.Instance.getWelcomeInfo());
					}

					//执行到这里，VPN已经建立起来了，执行真正的VPN转发
					runVPN();
				} else {
					//VPN被关掉之后，循环依然执行，每次sleep 100毫秒
					Thread.sleep(100);
				}
			}
		} catch (InterruptedException e) {
			System.out.println(e);
		} catch (Exception e) {
			e.printStackTrace();
			writeLog("Fatal error: %s",e.toString());
		} finally {
			writeLog("SmartProxy terminated.");
			dispose();
		}
	}

	/**
	 * 真正的VPN数据处理逻辑，其实是个无限循环，不停地去读取数据
	 * @throws Exception
     */
	private void runVPN() throws Exception {
		this.m_VPNInterface = establishVPN();
		this.m_VPNOutputStream = new FileOutputStream(m_VPNInterface.getFileDescriptor());
		FileInputStream in = new FileInputStream(m_VPNInterface.getFileDescriptor());
		int size = 0;
		while (size != -1 && IsRunning) {
			while ((size = in.read(m_Packet)) > 0 && IsRunning) {  //read是阻塞操作，未读取到数据会一直阻塞
				if(m_DnsProxy.Stopped||m_TcpProxyServer.Stopped){
					in.close();
					throw new Exception("LocalServer stopped.");
				}
				onIPPacketReceived(m_IPHeader, size);
			}
			Thread.sleep(100);
		}
		in.close();
		disconnectVPN();
	}

	/**
	 * 读取到VPN中（也就是虚拟网卡）的包之后的处理过程
	 * @param ipHeader
	 * @param size
	 * @throws IOException
     */
	void onIPPacketReceived(IPHeader ipHeader, int size) throws IOException {
		switch (ipHeader.getProtocol()) {
		case IPHeader.TCP:
			TCPHeader tcpHeader =m_TCPHeader;
			tcpHeader.m_Offset=ipHeader.getHeaderLength();
			if (ipHeader.getSourceIP() == LOCAL_IP) {
				// 收到来自本地TCP代理服务器数据，说明是隧道返回的数据
				// 查询之前的NAT映射表，修改目标地址，再次写入VPN流
				if (tcpHeader.getSourcePort() == m_TcpProxyServer.Port) {
					NatSession session =NatSessionManager.getSession(tcpHeader.getDestinationPort());
					if (session != null) {
						ipHeader.setSourceIP(ipHeader.getDestinationIP());
						tcpHeader.setSourcePort(session.RemotePort);
						ipHeader.setDestinationIP(LOCAL_IP);
						
						CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);
						m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, size);
						m_ReceivedBytes+=size;
					}else {
						System.out.printf("NoSession: %s %s\n", ipHeader.toString(),tcpHeader.toString());
					}
				} else {
					//从VPN流中读取到发送出去的包，则需要建立NAT映射，并将其转发到TCP代理服务器（转发其实是重新又写入了VPN流中）

					// 添加端口映射
					int portKey=tcpHeader.getSourcePort();
					NatSession session=NatSessionManager.getSession(portKey);
					if(session==null||session.RemoteIP!=ipHeader.getDestinationIP()||session.RemotePort!=tcpHeader.getDestinationPort()){
						session=NatSessionManager.createSession(portKey, ipHeader.getDestinationIP(), tcpHeader.getDestinationPort());
					}
					
					session.LastNanoTime=System.nanoTime();
					session.PacketSent++;//注意顺序
					
					int tcpDataSize=ipHeader.getDataLength()-tcpHeader.getHeaderLength();
					if(session.PacketSent==2&&tcpDataSize==0){
						return;//丢弃tcp握手的第二个ACK报文。因为客户端发数据的时候也会带上ACK，这样可以在服务器Accept之前分析出HOST信息。
					}
					
					//分析数据，找到host
					if(session.BytesSent==0&&tcpDataSize>10){
						int dataOffset=tcpHeader.m_Offset+tcpHeader.getHeaderLength();
						String host=HttpHostHeaderParser.parseHost(tcpHeader.m_Data, dataOffset, tcpDataSize);
						if(host!=null){
							session.RemoteHost=host;
						}
					}
 
					// 转发给本地TCP服务器
					ipHeader.setSourceIP(ipHeader.getDestinationIP());
					ipHeader.setDestinationIP(LOCAL_IP);
					tcpHeader.setDestinationPort(m_TcpProxyServer.Port);

					CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);
					m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, size);
					session.BytesSent+=tcpDataSize;//注意顺序
					m_SentBytes+=size;
				}
			}
			break;
		case IPHeader.UDP:
			// 转发DNS数据包：目前只通过DNS代理处理了DNS查询的UDP包，其他数据直接丢弃了
			UDPHeader udpHeader =m_UDPHeader;
			udpHeader.m_Offset=ipHeader.getHeaderLength();
			if (ipHeader.getSourceIP() == LOCAL_IP && udpHeader.getDestinationPort() == 53) {
				m_DNSBuffer.clear();
				m_DNSBuffer.limit(ipHeader.getDataLength() - 8);
				DnsPacket dnsPacket=DnsPacket.FromBytes(m_DNSBuffer);
				if(dnsPacket!=null&&dnsPacket.Header.QuestionCount>0){
					m_DnsProxy.onDnsRequestReceived(ipHeader, udpHeader, dnsPacket);
				}
			}else {
				//TODO does not support UDP proxy
				Log.w(TAG, "a UDP packet is dropped:" + ipHeader.getDestinationIP());
			}
			break;
		}
	}

	private void waitUntilPreapred() {
		while (prepare(this) != null) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * 关键部分，告诉系统，建立VPN连接，获得ParcelFileDescriptor以便操作IP包
	 * @return
	 * @throws Exception
     */
	private ParcelFileDescriptor establishVPN() throws Exception {
		Builder builder = new Builder();
		builder.setMtu(ProxyConfig.Instance.getMTU());
		if(ProxyConfig.IS_DEBUG)
			System.out.printf("setMtu: %d\n", ProxyConfig.Instance.getMTU());
		
		IPAddress ipAddress=ProxyConfig.Instance.getDefaultLocalIP();
		LOCAL_IP = CommonMethods.ipStringToInt(ipAddress.Address);	
		builder.addAddress(ipAddress.Address, ipAddress.PrefixLength);
		if(ProxyConfig.IS_DEBUG)
			System.out.printf("addAddress: %s/%d\n", ipAddress.Address,ipAddress.PrefixLength);
		
		for (ProxyConfig.IPAddress dns : ProxyConfig.Instance.getDnsList()) {
			builder.addDnsServer(dns.Address);
			if(ProxyConfig.IS_DEBUG)
				System.out.printf("addDnsServer: %s\n", dns.Address);
		}

		//自定义路由设置
		if(ProxyConfig.Instance.getRouteList().size()>0){
			for (ProxyConfig.IPAddress routeAddress : ProxyConfig.Instance.getRouteList()) {
				builder.addRoute(routeAddress.Address,routeAddress.PrefixLength);
				if(ProxyConfig.IS_DEBUG)
					System.out.printf("addRoute: %s/%d\n", routeAddress.Address,routeAddress.PrefixLength);
			}
			builder.addRoute(CommonMethods.ipIntToString(ProxyConfig.FAKE_NETWORK_IP), 16);
			
			if(ProxyConfig.IS_DEBUG)
				System.out.printf("addRoute for FAKE_NETWORK: %s/%d\n", CommonMethods.ipIntToString(ProxyConfig.FAKE_NETWORK_IP),16);
		}else {
			builder.addRoute("0.0.0.0",0);
			if(ProxyConfig.IS_DEBUG)
				System.out.printf("addDefaultRoute: 0.0.0.0/0\n");
		}
		

		//为系统的DNS添加路由设置，DNS必须通过VPN
		Class<?> SystemProperties = Class.forName("android.os.SystemProperties");
		Method method = SystemProperties.getMethod("get", new Class[] { String.class });
		Set<String> servers = new HashSet<String>();
		for (String name : new String[] { "net.dns1", "net.dns2", "net.dns3", "net.dns4", }) {
			String value = (String) method.invoke(null, name);
			if (value != null && !"".equals(value) && !servers.contains(value)) {
				servers.add(value);
				builder.addRoute(value, 32);
				if(ProxyConfig.IS_DEBUG)
					System.out.printf("%s=%s\n", name, value);
			}
		}
 
		Intent intent=new Intent(this, MainActivity.class);
		PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);
		builder.setConfigureIntent(pendingIntent);

		builder.setSession(ProxyConfig.Instance.getSessionName());
		ParcelFileDescriptor pfdDescriptor = builder.establish();
		onStatusChanged(ProxyConfig.Instance.getSessionName()+getString(R.string.vpn_connected_status), true);
		return pfdDescriptor;
	}

	/**
	 * 断开VPN，主要是关闭之前获得的ParcelFileDescriptor
	 */
	public void disconnectVPN() {
		try {
			if (m_VPNInterface != null) {
				m_VPNInterface.close();
				m_VPNInterface = null;
			}
		} catch (Exception e) {
			// ignore
		}
		onStatusChanged(ProxyConfig.Instance.getSessionName()+getString(R.string.vpn_disconnected_status), false);
		this.m_VPNOutputStream = null;
	}
	
	private synchronized void dispose() {
		// 断开VPN
		disconnectVPN();

		// 停止TcpServer
		if (m_TcpProxyServer != null) {
			m_TcpProxyServer.stop();
			m_TcpProxyServer = null;
			writeLog("LocalTcpServer stopped.");
		}

		// 停止DNS解析器
		if (m_DnsProxy != null) {
			m_DnsProxy.stop();
			m_DnsProxy = null;
			writeLog("LocalDnsProxy stopped.");
		}
		
		stopSelf();
		IsRunning = false;
		System.exit(0);
	}
	
	@Override
	public void onDestroy() {
		System.out.printf("VPNService(%s) destoried.\n", ID);
		if (m_VPNThread != null) {
			m_VPNThread.interrupt();
		}
	}

}
