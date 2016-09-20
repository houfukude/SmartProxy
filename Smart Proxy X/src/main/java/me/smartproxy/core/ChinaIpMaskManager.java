package me.smartproxy.core;

import java.io.IOException;
import java.io.InputStream;

import me.smartproxy.tcpip.CommonMethods;

import android.util.SparseIntArray;


/**
 * 中国的IP地址管理器，用了判断IP地址是否来自中国
 */
public class ChinaIpMaskManager {

    static SparseIntArray ChinaIpMaskDict = new SparseIntArray(3000);   //所有中国的IP地址及掩码
    static SparseIntArray MaskDict = new SparseIntArray();                    //所有的掩码集合

    /**
     * 判断是不是中国的IP地址<br/>
     * 从掩码集合里面，逐个去匹配，获取网络地址，然后再根据网络地址去查是否为中国的IP
     *
     * @param ip
     * @return
     */
    public static boolean isIPInChina(int ip) {
        boolean found = false;
        for (int i = 0; i < MaskDict.size(); i++) {
            int mask = MaskDict.keyAt(i);
            int networkIP = ip & mask;
            int mask2 = ChinaIpMaskDict.get(networkIP);
            if (mask2 == mask) {
                found = true;
                break;
            }
        }
        return found;
    }

    /**
     * 从文件中加载中国的IP地址
     *
     * @param inputStream
     */
    public static void loadFromFile(InputStream inputStream) {
        int count = 0;
        try {
            byte[] buffer = new byte[4096];
            while ((count = inputStream.read(buffer)) > 0) {
                for (int i = 0; i < count; i += 8) {
                    int ip = CommonMethods.readInt(buffer, i);
                    int mask = CommonMethods.readInt(buffer, i + 4);
                    ChinaIpMaskDict.put(ip, mask);
                    MaskDict.put(mask, mask);
                }
            }
            inputStream.close();
            System.out.printf("ChinaIpMask records count: %d\n", ChinaIpMaskDict.size());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
