/*
 * Copyright (c) 2015, Blake
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior
 * written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package me.smartproxy.tunnel.shadowsocks;

import java.io.UnsupportedEncodingException;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import me.smartproxy.util.EncryptUtil;

/**
 * Shadowsocks password KEY generator
 */
public class ShadowsocksKey implements SecretKey {

    private Logger logger = Logger.getLogger(ShadowsocksKey.class.getName());

    private final static int KEY_LENGTH = 32;
    private byte[] key;
    private int length;

    public ShadowsocksKey(String password) {
        length = KEY_LENGTH;
        key = init(password);
    }

    public ShadowsocksKey(String password, int length) {
        this.length = length;
        key = init(password);
    }

    private byte[] init(String password) {
        byte[] rawKey = new byte[this.length];

        byte[] passwordBytes = null;
        try {
            passwordBytes = password.getBytes("utf-8");
        } catch (UnsupportedEncodingException e) {
            passwordBytes = password.getBytes();
        }

        int i = 0;
        byte[] lastHash = null;
        while (i < rawKey.length) {
            byte[] temp = null;
            if (i == 0){
                temp = passwordBytes;
            }else {
                temp = new byte[lastHash.length + passwordBytes.length];
                System.arraycopy(lastHash, 0, temp, 0, lastHash.length);
                System.arraycopy(passwordBytes, 0, temp, lastHash.length, passwordBytes.length);
            }

            lastHash = EncryptUtil.md5(temp);

            //计算还需要多少字节的key,只复制需要的部分
            int remainSize = this.length - i;
            int copySize = remainSize > lastHash.length? lastHash.length : remainSize;

            System.arraycopy(lastHash, 0, rawKey, i, copySize);

            i += lastHash.length;
        }

        return rawKey;
    }

    @Override
    public String getAlgorithm() {
        return "shadowsocks";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key;
    }
}
