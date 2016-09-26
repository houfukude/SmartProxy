package me.smartproxy.tunnel.shadowsocks.bcencryptor;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;

/**
 * Created by hy on 9/26/16.
 */

public class Chacha20Encryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamCipher createCipher(){
        return new ChaChaEngine(20);
    }
}

