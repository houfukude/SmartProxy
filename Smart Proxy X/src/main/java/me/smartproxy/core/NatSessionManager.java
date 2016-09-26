package me.smartproxy.core;

import me.smartproxy.tcpip.CommonMethods;

import android.util.SparseArray;


/**
 * NAT管理器，用来创建或者获取NAT配置<br>
 * 每一条NAT配置以本地端口号作为key，保存本地端口、远程IP、远程端口和创建时间
 */
public class NatSessionManager {

    static final int MAX_SESSION_COUNT = 60;

    static final long SESSION_TIMEOUT_NS = 60 * 1000000000L;

    static final SparseArray<NatSession> Sessions = new SparseArray<NatSession>();

    public static NatSession getSession(int portKey) {
        return Sessions.get(portKey);
    }

    public static int getSessionCount() {
        return Sessions.size();
    }

    /**
     * 清理失效的NAT会话
     */
    static void clearExpiredSessions() {
        long now = System.nanoTime();
        for (int i = Sessions.size() - 1; i >= 0; i--) {
            NatSession session = Sessions.valueAt(i);
            if (now - session.LastNanoTime > SESSION_TIMEOUT_NS) {
                Sessions.removeAt(i);
            }
        }
    }

    /**
     * 创建NAT规则
     * @param portKey 本地端口
     * @param remoteIP 远程IP
     * @param remotePort 远程端口
     * @return
     */
    public static NatSession createSession(int portKey, int remoteIP, short remotePort) {
        if (Sessions.size() > MAX_SESSION_COUNT) {
            clearExpiredSessions();//清理过期的会话。
        }

        NatSession session = new NatSession();
        session.LastNanoTime = System.nanoTime();
        session.RemoteIP = remoteIP;
        session.RemotePort = remotePort;

        if (ProxyConfig.isFakeIP(remoteIP)) {
            session.RemoteHost = DnsProxy.reverseLookup(remoteIP);
        }

        if (session.RemoteHost == null) {
            session.RemoteHost = CommonMethods.ipIntToString(remoteIP);
        }
        Sessions.put(portKey, session);
        return session;
    }
}
