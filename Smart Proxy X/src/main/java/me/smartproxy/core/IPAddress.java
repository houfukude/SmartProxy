package me.smartproxy.core;

import android.annotation.SuppressLint;

/**
 * IP地址辅助类，支持两种格式的构造：<br>
 *     1、IPAddress(String address,int prefixLength):address表示地址，prefixLength表示网段长度
 *     2、IPAddress(String ipAddresString):ipAddresString支持带个地址，也支持'IP地址/掩码长度'的格式
 *
 */
public class IPAddress {
    public final String Address;
    public final int PrefixLength;

	public IPAddress(String address, int prefixLength) {
        this.Address=address;
        this.PrefixLength=prefixLength;
    }

    public IPAddress(String ipAddresString){
        String[] arrStrings=ipAddresString.split("/");
        String address=arrStrings[0];
        int prefixLength=32;
        if(arrStrings.length>1){
            prefixLength=Integer.parseInt(arrStrings[1]);
        }
        this.Address=address;
        this.PrefixLength=prefixLength;
    }

    @SuppressLint("DefaultLocale")
    @Override
    public String toString() {
        return String.format("%s/%d", Address, PrefixLength);
    }

    @Override
    public boolean equals(Object o) {
         if(o==null){
             return false;
         }
         else {
            return this.toString().equals(o.toString());
         }
    }
}
