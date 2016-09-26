package me.smartproxy.tunnel.shadowsocks.bcencryptor;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Salsa20Engine;

/**
 * Created by hy on 9/26/16.
 */

public class Salsa20Encryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamCipher createCipher(){
        return new Salsa20Engine();
    }
}

