package me.smartproxy.core;
 
import android.os.Build;

import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import me.smartproxy.tcpip.CommonMethods;
import me.smartproxy.tunnel.Config;
import me.smartproxy.tunnel.httpconnect.HttpConnectConfig;
import me.smartproxy.tunnel.shadowsocks.ShadowsocksConfig;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;


/**
 * VPN代理的相关配置
 */
public class ProxyConfig {
	public static final ProxyConfig Instance=new ProxyConfig();
	public final static boolean IS_DEBUG=true;
	public static String AppInstallID;			//用户安装后生成的唯一ID，存储在SharedPreferences中
	public static String AppVersion;

	public final static int FAKE_NETWORK_MASK=CommonMethods.ipStringToInt("255.255.0.0");
	public final static int FAKE_NETWORK_IP=CommonMethods.ipStringToInt("10.231.0.0");
	
    ArrayList<IPAddress> m_IpList;			//VPN使用的本地地址列表，通过ip进行配置
    ArrayList<IPAddress> m_DnsList;			//DNS服务器列表，通过dns进行配置
    ArrayList<IPAddress> m_RouteList;		//自定义的VPN路由表，通过route进行配置
    ArrayList<Config> m_ProxyList;			//配置文件中所有的代理，可能不止一个，通过proxy进行配置
    HashMap<String, Boolean> m_DomainMap;  //无需或者强制使用代理的域名Map，value为true表示必须使用代理，通过direct_domain和proxy_domain进行配置，前者表示不使用代理
    
    int m_dns_ttl;							//dns的有效期，可以通过dns_ttl进行配置，默认为30
    String m_welcome_info;					//连接成功后的欢迎消息，通过welcome_info进行配置
    String m_session_name;					//VPN的session name，默认为代理服务器的主机名，通过session_name进行配置
    String m_user_agent;					//http请求使用的user-agent，通过user_agent进行配置，如果为空，会获取系统变量http.agent
    boolean m_outside_china_use_proxy=true;		//配置非中国ip是否使用代理，通过outside_china_use_proxy进行配置，默认为true

    /**
	 * 配置http隧道是否要尝试发送请求头的一部分，让请求头的host在第二个包里面发送，从而绕过机房的白名单机制。
	 */
	boolean m_isolate_http_host_header=true;	//配置是否使用m_isolate_http_host_header，通过isolate_http_host_header进行配置
    int m_mtu;									//配置VPN的mtu，默认为20000，值必须在1400和20000之间

	boolean m_is_global_mode = true; 			//是否使用全局代理
    
    Timer m_Timer;


	public ProxyConfig(){
    	m_IpList=new ArrayList<IPAddress>();
    	m_DnsList=new ArrayList<IPAddress>();
    	m_RouteList=new ArrayList<IPAddress>();
    	m_ProxyList=new ArrayList<Config>();
    	m_DomainMap=new HashMap<String, Boolean>();

    	m_Timer=new Timer();
    	m_Timer.schedule(m_Task, 120000, 120000);//每两分钟刷新一次。
    }

	//刷新远程代理服务器DNS缓存的定时任务
	TimerTask m_Task = new TimerTask() {
		@Override
		public void run() {
			refreshProxyServer();//定时更新dns缓存
		}

		//定时更新远程代理服务器的DNS缓存，这里其实可以实现心跳机制，检测代理服务器的连接性
		void refreshProxyServer() {
			try {
				for (int i = 0; i < m_ProxyList.size(); i++) {
					try {
						Config config = m_ProxyList.get(i);
						InetAddress address = InetAddress.getByName(config.ServerAddress.getHostName());
						if (address != null && !address.equals(config.ServerAddress.getAddress())) {
							config.ServerAddress = new InetSocketAddress(address, config.ServerAddress.getPort());
						}
					} catch (Exception e) {
					}
				}
			} catch (Exception e) {

			}
		}
	};


	public static boolean isFakeIP(int ip) {
		return (ip & ProxyConfig.FAKE_NETWORK_MASK) == ProxyConfig.FAKE_NETWORK_IP;
	}

	/**
	 * 获取默认的远程代理<br/>
	 * @return
     */
	public Config getDefaultProxy(){
    	if(m_ProxyList.size()>0){
    		return m_ProxyList.get(0);
    	}else {
			return null;
		}
    }

    /**
	 * 根据要连接的远程地址来选择代理配置，目前只返回了默认的代理<br/>
	 * 其实可以考虑负载均衡？或者各个远程代理的可连接性及速度。
	 * @param destAddress
	 * @return
     */
    public Config getDefaultTunnelConfig(InetSocketAddress destAddress){
    	return getDefaultProxy();
    }

	/**
	 * 获取为VPN配置的本地IP地址
	 * @return
     */
    public IPAddress getDefaultLocalIP(){
    	if(m_IpList.size()>0){
    		return m_IpList.get(0);
    	}else {
			return new IPAddress("10.8.0.2",32);
		}
    }
    
    public ArrayList<IPAddress> getDnsList(){
    	return m_DnsList;
    }

    public ArrayList<IPAddress> getRouteList(){
    	return m_RouteList;
    }
    
    public int getDnsTTL(){
    	if(m_dns_ttl<30){
    		m_dns_ttl=30;
    	}
    	return m_dns_ttl;
    }
    
    public String getWelcomeInfo(){
    	return m_welcome_info;
    }

    /**
	 * 获取SessionName，用于设置VPN的session name，目前取默认代理的主机名
	 * @return
     */
    public String getSessionName(){
    	if(m_session_name==null){
    		m_session_name=getDefaultProxy().ServerAddress.getHostName();
    	}
    	return m_session_name;
    }

    /**
	 * 获取User-Agent，
	 * @return
     */
    public String getUserAgent(){
    	if(m_user_agent==null||m_user_agent.isEmpty()){
    		m_user_agent = System.getProperty("http.agent");
    	}
    	return m_user_agent;
    }
    
    public int getMTU(){
    	if(m_mtu>1400&&m_mtu<=20000){
    		return m_mtu;
    	}else {
			return 20000;
		}
    }

    /**
	 * 判断指定的domain是否需要代理，会逐级查询其子域名，返回true表示需要代理
	 * @param domain
	 * @return
     */
	private Boolean getDomainState(String domain){
		domain=domain.toLowerCase();
		while (domain.length()>0) {
			Boolean stateBoolean=m_DomainMap.get(domain);
			if(stateBoolean!=null){
				return stateBoolean;
			}else {
				int start=domain.indexOf('.')+1;
				if(start>0 && start<domain.length()){
					domain=domain.substring(start);
				}else {
					return null;
				}
			}
		}
		return null;
	}

	/**
	 * 根据host或者ip判断是否需要使用代理
	 * @param host
	 * @param ip
     * @return
     */
    public boolean needProxy(String host,int ip){
		if (m_is_global_mode){
			return true;
		}

    	if(host!=null){
    		Boolean stateBoolean=getDomainState(host);
    		if(stateBoolean!=null){
    			return stateBoolean.booleanValue();
    		}
    	}
    	
    	if(isFakeIP(ip))
    		return true;
    	
    	if(m_outside_china_use_proxy&&ip!=0){
    		return !ChinaIpMaskManager.isIPInChina(ip);
    	}
    	return false;
    }
    
    public boolean isIsolateHttpHostHeader(){
    	return m_isolate_http_host_header;
    }


    /**
	 * 根据指定的url，下载proxy配置
	 * @param url
	 * @return
	 * @throws Exception
     */
    private String[] downloadConfig(String url) throws Exception{
    	try {
    		HttpClient client=new DefaultHttpClient();
        	HttpGet requestGet=new HttpGet(url);
        	
        	requestGet.addHeader("X-Android-MODEL", Build.MODEL);
        	requestGet.addHeader("X-Android-SDK_INT",Integer.toString(Build.VERSION.SDK_INT));
        	requestGet.addHeader("X-Android-RELEASE", Build.VERSION.RELEASE);
        	requestGet.addHeader("X-App-Version", AppVersion);
        	requestGet.addHeader("X-App-Install-ID", AppInstallID);
        	requestGet.setHeader("User-Agent", System.getProperty("http.agent"));
            HttpResponse response=client.execute(requestGet);
            
            String configString=EntityUtils.toString(response.getEntity(),"UTF-8");
            String[] lines=configString.split("\\n");
            return lines;
    	}
    	catch(Exception e){
    		throw new Exception(String.format("Download config file from %s failed.", url));
    	}
    }

    /**
	 * 解析本地的配置文件，返回文件内容，按行分隔的数组
	 * @param path
	 * @return
	 * @throws Exception
     */
    private String[] readConfigFromFile(String path) throws Exception {
    	StringBuilder sBuilder=new StringBuilder();
        FileInputStream inputStream=null;
    	try {
    		byte[] buffer=new byte[8192];
    		int count=0;
    		inputStream=new FileInputStream(path);
    		while ((count=inputStream.read(buffer))>0) {
				 sBuilder.append(new String(buffer,0,count,"UTF-8"));
			}
    		return sBuilder.toString().split("\\n");
		} catch (Exception e) {
			throw new Exception(String.format("Can't read config file: %s", path));
		}finally{
			if(inputStream!=null){
				try {
					inputStream.close();
				} catch (Exception e2) {
				}
			}
		}
    }

    /**
	 * 根据指定的url，加载proxy配置
	 * @param url 如果以'/'开头，表示是本地文件路径，否则当做url处理
	 * @throws Exception
     */
    public void loadFromUrl(String url) throws Exception{
    	String[] lines=null;
    	if(url.charAt(0)=='/'){
    		lines=readConfigFromFile(url);
    	}else {
    		lines=downloadConfig(url);
		}
    
        m_IpList.clear();
        m_DnsList.clear();
        m_RouteList.clear();
        m_ProxyList.clear();
        m_DomainMap.clear();
        
        int lineNumber=0;
        for (String line : lines) {
        	lineNumber++;
			String[] items=line.split("\\s+");
			if(items.length<2){
				continue;
			}
			
			String tagString=items[0].toLowerCase(Locale.ENGLISH).trim();
			try {
				if(!tagString.startsWith("#")){
					if(ProxyConfig.IS_DEBUG)
						System.out.println(line);
					
					 if(tagString.equals("ip")){
						 addIPAddressToList(items, 1, m_IpList);
					 }else if(tagString.equals("dns")){
						 addIPAddressToList(items, 1, m_DnsList);
					 }else if(tagString.equals("route")){
						 addIPAddressToList(items, 1, m_RouteList);
					 }else if(tagString.equals("proxy")){
						 addProxyToList(items, 1);
					 }else if(tagString.equals("direct_domain")){
						 addDomainToHashMap(items, 1, false);
					 }else if(tagString.equals("proxy_domain")){
						 addDomainToHashMap(items, 1, true);
					 }else if(tagString.equals("dns_ttl")) {
						 m_dns_ttl=Integer.parseInt(items[1]);
					 }else if(tagString.equals("welcome_info")){
						 m_welcome_info=line.substring(line.indexOf(" ")).trim();
					 }else if(tagString.equals("session_name")){
						 m_session_name=items[1];
					 }else if(tagString.equals("user_agent")){
						 m_user_agent=line.substring(line.indexOf(" ")).trim();
					 }else if(tagString.equals("outside_china_use_proxy")) {
						 m_outside_china_use_proxy=convertToBool(items[1]);
					 }else if(tagString.equals("isolate_http_host_header")){
						 m_isolate_http_host_header=convertToBool(items[1]);
					 }else if(tagString.equals("mtu")) {
						 m_mtu=Integer.parseInt(items[1]);
					 }
				}
			} catch (Exception e) {
				throw new Exception(String.format("SmartProxy config file parse error: line:%d, tag:%s, error:%s", lineNumber,tagString,e));
			}
			
		}
        
        //查找默认代理。
        if(m_ProxyList.size()==0){
        	tryAddProxy(lines);
        }
    }

    /**
	 * 可能之前解析代理出错了（中间抛出了异常，或者其他原因导致解析失败），这里再用正则表达式处理一下
	 * @param lines
     */
    private void tryAddProxy(String[] lines){
    	 for (String line : lines) {
    		 Pattern p=Pattern.compile("proxy\\s+([^:]+):(\\d+)",Pattern.CASE_INSENSITIVE);
        	 Matcher m=p.matcher(line);
        	 while(m.find()){
        		 HttpConnectConfig config=new HttpConnectConfig();
        		 config.ServerAddress= new InetSocketAddress(m.group(1), Integer.parseInt(m.group(2)));
        		 if(!m_ProxyList.contains(config)){
    				 m_ProxyList.add(config);
    				 m_DomainMap.put(config.ServerAddress.getHostName(), false);
    			 }
        	 }
		}
    }

    /**
	 * 根据配置，添加代理配置，目前支持http代理和shadowsocks代理，ss://开头的为shadowsocks代理，http://开头的是http代理
	 * @param items
	 * @param offset
	 * @throws Exception
     */
    private void addProxyToList(String[] items,int offset) throws Exception{
    	for (int i = offset; i < items.length; i++) {
			 String proxyString=items[i].trim();
			 Config config=null;
			 if(proxyString.startsWith("ss://")){
				 config=ShadowsocksConfig.parse(proxyString);
			 }else {
				 if(!proxyString.toLowerCase().startsWith("http://")){
					 proxyString="http://"+proxyString;
				 }
				 config=HttpConnectConfig.parse(proxyString);
			 }
			 if(!m_ProxyList.contains(config)){
				 m_ProxyList.add(config);
				 m_DomainMap.put(config.ServerAddress.getHostName(), false); //将代理服务器的域名设置为无需代理
			 }
		}
    }


	/**
	 * 将域名加入预定义的无需或强制使用代理的map中
	 * @param items
	 * @param offset
	 * @param state
     */
    private void addDomainToHashMap(String[] items,int offset,Boolean state) {
		for (int i = offset; i < items.length; i++) {
			String domainString=items[i].toLowerCase().trim();
			if(domainString.charAt(0)=='.'){
				domainString=domainString.substring(1);
			}
			m_DomainMap.put(domainString, state);
		}
	}
    
    private boolean convertToBool(String valueString){
    	if(valueString==null||valueString.isEmpty())
    		return false;
    	 valueString=valueString.toLowerCase(Locale.ENGLISH).trim();
		 if(valueString.equals("on")||valueString.equals("1")||valueString.equals("true")||valueString.equals("yes")){
			 return true;
		 }else {
			return false;
		}
    }
    

    private void addIPAddressToList(String[] items,int offset,ArrayList<IPAddress> list){
    	for (int i = offset; i < items.length; i++) {
			String item=items[i].trim().toLowerCase();
			if(item.startsWith("#")){
				break;
			}else {
				IPAddress ip=new IPAddress(item);
				 if(!list.contains(ip)){
					  list.add(ip);
				 }
			}
		}
    }
    
}
