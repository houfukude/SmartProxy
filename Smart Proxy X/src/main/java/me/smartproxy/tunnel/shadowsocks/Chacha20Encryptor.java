package me.smartproxy.tunnel.shadowsocks;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.RC4Engine;

/**
 * Created by hy on 9/26/16.
 */

public class Chacha20Encryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamCipher createCipher(){
        return new ChaChaEngine(20);
    }
}

