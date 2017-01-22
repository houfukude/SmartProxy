package me.smartproxy.core;

import android.util.Log;
import android.util.SparseIntArray;

import java.io.IOException;
import java.io.InputStream;

import me.smartproxy.tcpip.CommonMethods;


public class ChinaIpMaskManager {

    private static final String TAG = "ChinaIpMaskManager";
    static SparseIntArray ChinaIpMaskDict = new SparseIntArray(3000);
    static SparseIntArray MaskDict = new SparseIntArray();

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
                    Log.d(TAG, String.format("%s/%s", CommonMethods.ipIntToInet4Address(ip), CommonMethods.ipIntToInet4Address(mask)));
                }
            }
            inputStream.close();
            Log.d(TAG, String.format("ChinaIpMask records count: %d\n", ChinaIpMaskDict.size()));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
