package me.smartproxy.tunnel.socks5;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;

import me.smartproxy.tunnel.Config;
import me.smartproxy.tunnel.Tunnel;

/**
 * Created by hy on 9/22/16.<br/>
 * https://tools.ietf.org/html/rfc1928<br/>
 * https://en.wikipedia.org/wiki/SOCKS#SOCKS5<br/>
 * https://samsclass.info/122/proj/how-socks5-works.html<br/>
 *
 *
 */
public class Socks5Tunnel extends Tunnel {

    //初始握手的几种状态
    enum ConnectStage {INIT, GREETING, AUTHENTICATE,  CONNECTING, ESTABLISHED};

    Socks5Config m_config;
    ConnectStage stage;


    public Socks5Tunnel(Config config, Selector selector) throws IOException{
        super(config.ServerAddress, selector);

        m_config = (Socks5Config)config;
        stage = ConnectStage.INIT;
    }


    @Override
    protected void onConnected(ByteBuffer buffer) throws Exception {
        //先进行握手
        buffer.clear();
        buffer.put((byte) 0x05); //version
        buffer.put((byte) 0x02); //two methods
        buffer.put((byte) 0x00); //no auth
        buffer.put((byte) 0x02); //username, password
        buffer.flip();

        if (this.write(buffer, true)) {//发送连接请求到代理服务器
            this.beginReceive();//开始接收代理服务器响应数据
        }

        stage = ConnectStage.GREETING;
    }

    @Override
    protected boolean isTunnelEstablished() {
        return stage == ConnectStage.ESTABLISHED;
    }

    @Override
    protected void beforeSend(ByteBuffer buffer) throws Exception {
        //do nothing
    }

    @Override
    protected void afterReceived(ByteBuffer buffer) throws Exception {
        if (stage != ConnectStage.ESTABLISHED) { //未建立连接,处理握手的信息
            byte ver = buffer.get();
            byte status = buffer.get();

            buffer.limit(buffer.position());
            switch (stage) {
                case GREETING:
                    if (status == 0x00){ //no auth required
                        stage = ConnectStage.CONNECTING;
                        sendConnectRequest();
                    }else if (status == 0x02){ //auth method, current only support username password auth
                        stage = ConnectStage.AUTHENTICATE;
                        sendAuthRequest();
                    }else  {
                        throw new Exception("Cannot establish Socks connection, handshake status:" + status);
                    }
                    break;
                case AUTHENTICATE:
                    if (status == 0x00){ //success
                        stage = ConnectStage.CONNECTING;
                        sendConnectRequest();
                    }else {
                        throw new Exception("Cannot establish Socks connection, auth status:" + status);
                    }
                    break;
                case CONNECTING:
                    if (status == 0x00){//success
                        stage = ConnectStage.ESTABLISHED;
                        onTunnelEstablished();
                    }else {
                        throw new Exception("Cannot establish Socks connection, connecting status:" + status);
                    }
                    break;
            }
        }
    }

    /**
     * 发送授权验证的包
     * @throws Exception
     */
    private void sendAuthRequest() throws Exception{
        if (m_config.UserName == null || m_config.Password == null){
            throw new Exception("Cannot establish Socks connection, auth error, no Username or Password supplied");
        }

        ByteBuffer buffer = GL_BUFFER;
        buffer.clear();

        buffer.put((byte) 0x01); //version

        byte[] nameBytes = m_config.UserName.getBytes();
        byte[] passBytes = m_config.Password.getBytes();

        //username length and data
        buffer.put((byte) nameBytes.length);
        buffer.put(nameBytes);

        //password length and data
        buffer.put((byte) passBytes.length);
        buffer.put(passBytes);
        buffer.flip();

        if (this.write(buffer, true)) {//发送连接请求到代理服务器
            this.beginReceive();//开始接收代理服务器响应数据
        }
    }

    /**
     * 发送连接的包
     * @throws Exception
     */
    private void sendConnectRequest() throws Exception{
        ByteBuffer buffer = GL_BUFFER;
        buffer.clear();

        buffer.put((byte) 0x05); //version
        buffer.put((byte) 0x01); //CONNECT:0x01, BIND:0x02, UDP:0x03
        buffer.put((byte) 0x00); //reserved
        buffer.put((byte) 0x03); //address type: IPV4 : 0x01, domain: 0x03, ipv6: 0x04

        //domain address
        byte[] domainBytes= m_DestAddress.getHostName().getBytes();
        buffer.put((byte)domainBytes.length);//domain length;
        buffer.put(domainBytes);

        //two byte port
        buffer.putShort((short) m_DestAddress.getPort()); //port
        buffer.flip();

        if (this.write(buffer, true)) {//发送连接请求到代理服务器
            this.beginReceive();//开始接收代理服务器响应数据
        }
    }

    @Override
    protected void onDispose() {
        stage = ConnectStage.INIT;
    }
}
