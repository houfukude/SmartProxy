package me.smartproxy.tunnel.shadowsocks;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;

/**
 * Created by hy on 9/26/16.
 */

public class Cast5CFBEncryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamCipher createCipher(){
        return new CFBBlockCipher(new CAST5Engine(), method.ivLength * 8);
    }
}

