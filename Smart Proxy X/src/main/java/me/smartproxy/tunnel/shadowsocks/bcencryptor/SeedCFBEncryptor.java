package me.smartproxy.tunnel.shadowsocks.bcencryptor;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;

/**
 * Created by hy on 9/26/16.
 */

public class SeedCFBEncryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamCipher createCipher(){
        return new CFBBlockCipher(new SEEDEngine(), method.ivLength * 8);
    }
}

