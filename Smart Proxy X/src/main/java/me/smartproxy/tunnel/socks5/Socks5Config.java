package me.smartproxy.tunnel.socks5;

import android.net.Uri;

import java.net.InetSocketAddress;

import me.smartproxy.tunnel.Config;

/**
 * Socks5配置,支持用户名和密码验证
 * Created by hy on 9/22/16.
 */
public class Socks5Config extends Config {
    public String Password;
    public String UserName;

    public static Socks5Config parse(String proxyInfo) {
        Socks5Config config = new Socks5Config();
        if (proxyInfo.startsWith("socks5://")){
            proxyInfo = "socks://" + proxyInfo.substring(9);
        }
        Uri uri = Uri.parse(proxyInfo);
        String userInfoString = uri.getUserInfo();
        if (userInfoString != null) {
            String[] userStrings = userInfoString.split(":");
            config.UserName = userStrings[0];
            if (userStrings.length >= 2) {
                config.Password = userStrings[1];
            }
        }
        config.ServerAddress = new InetSocketAddress(uri.getHost(), uri.getPort());
        return config;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null)
            return false;
        return this.toString().equals(o.toString());
    }

    @Override
    public String toString() {
        return String.format("socks5://%s:%s@%s", UserName, Password, ServerAddress);
    }
}
