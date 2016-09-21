package me.smartproxy.tunnel.httpconnect;

import android.util.Base64;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;

import me.smartproxy.core.ProxyConfig;
import me.smartproxy.tunnel.Tunnel;

/**
 * 基于http的隧道,使用http tunnel技术,即先进行CONNECT
 */
public class HttpConnectTunnel extends Tunnel {

    private boolean m_TunnelEstablished;
    private HttpConnectConfig m_Config;
    private int m_retryCount;               //重试proxy验证的次数

    public HttpConnectTunnel(HttpConnectConfig config, Selector selector) throws IOException {
        super(config.ServerAddress, selector);
        m_Config = config;
        m_retryCount = 0;
    }


    /**
     * so easy？<br/>
     * http代理在请求之前只需要发送个CONNECT指令就行了？
     *
     * @param buffer
     * @throws Exception
     */
    @Override
    protected void onConnected(ByteBuffer buffer) throws Exception {
        String request = String.format("CONNECT %s:%d HTTP/1.0\r\nProxy-Connection: keep-alive\r\nUser-Agent: %s\r\nX-App-Install-ID: %s\r\n\r\n",
                m_DestAddress.getHostName(),
                m_DestAddress.getPort(),
                ProxyConfig.Instance.getUserAgent(),
                ProxyConfig.AppInstallID);

        buffer.clear();
        buffer.put(request.getBytes());
        buffer.flip();
        if (this.write(buffer, true)) {//发送连接请求到代理服务器
            this.beginReceive();//开始接收代理服务器响应数据
        }
    }


    /**
     * 尝试发送请求头的一部分，让请求头的host在第二个包里面发送，从而绕过机房的白名单机制
     *
     * @param buffer
     * @throws Exception
     */
    void trySendPartOfHeader(ByteBuffer buffer) throws Exception {
        int bytesSent = 0;
        if (buffer.remaining() > 10) {
            int pos = buffer.position() + buffer.arrayOffset();
            String firString = new String(buffer.array(), pos, 10).toUpperCase();
            if (firString.startsWith("GET /") || firString.startsWith("POST /")) {
                int limit = buffer.limit();
                buffer.limit(buffer.position() + 10);
                super.write(buffer, false);
                bytesSent = 10 - buffer.remaining();
                buffer.limit(limit);
                if (ProxyConfig.IS_DEBUG)
                    System.out.printf("Send %d bytes(%s) to %s\n", bytesSent, firString, m_DestAddress);
            }
        }
    }


    @Override
    protected void beforeSend(ByteBuffer buffer) throws Exception {
        if (ProxyConfig.Instance.isIsolateHttpHostHeader()) {
            trySendPartOfHeader(buffer);//尝试发送请求头的一部分，让请求头的host在第二个包里面发送，从而绕过机房的白名单机制。
        }
    }

    /**
     * 未建立隧道链接的第一次接收，是CONNECT指令的响应，根据响应值判断http代理是否正常<br/>
     * 隧道建立后，无需对数据做任何处理
     *
     * @param buffer
     * @throws Exception
     */
    @Override
    protected void afterReceived(ByteBuffer buffer) throws Exception {
        if (!m_TunnelEstablished) {
            //收到代理服务器响应数据
            //分析响应并判断是否连接成功
            String response = new String(buffer.array(), buffer.position(), 12); //只取前12个字符
            if (response.matches("^HTTP/1.[01] 200$")) {
                buffer.limit(buffer.position());

                //连接成功
                m_TunnelEstablished = true;
                super.onTunnelEstablished();
            }else if(response.matches("^HTTP/1.[01] 407$")){ //代理服务器需要验证
                if (m_retryCount > 2){
                    throw new Exception("Cannot connect to Proxy Server, authentication failed");
                }else if (m_Config.UserName == null || m_Config.UserName.isEmpty()){
                    throw new Exception("Cannot connect to Proxy Server, no authentication info provided");
                }else { //发送认证信息
                    buffer.limit(buffer.position());
                    doProxyAuthentication();
                }

                m_retryCount ++;
            } else {
                throw new Exception(String.format("Proxy server responsed an error: %s", response));
            }
        }
    }

    /**
     * 发送proxy认证的信息
     */
    private void doProxyAuthentication() throws Exception {
        String credential = Base64.encodeToString((m_Config.UserName + ":" + m_Config.Password).getBytes(), Base64.NO_WRAP | Base64.DEFAULT);
        String request = String.format("CONNECT %s:%d HTTP/1.0\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic %s\r\nUser-Agent: %s\r\nX-App-Install-ID: %s\r\n\r\n",
                m_DestAddress.getHostName(),
                m_DestAddress.getPort(),
                credential,
                ProxyConfig.Instance.getUserAgent(),
                ProxyConfig.AppInstallID);

        ByteBuffer buffer = GL_BUFFER;
        buffer.clear();

        buffer.put(request.getBytes());
        buffer.flip();
        if (this.write(buffer, true)) {//发送连接请求到代理服务器
            this.beginReceive();//开始接收代理服务器响应数据
        }
    }

    @Override
    protected boolean isTunnelEstablished() {
        return m_TunnelEstablished;
    }

    @Override
    protected void onDispose() {
        m_Config = null;
    }


}
