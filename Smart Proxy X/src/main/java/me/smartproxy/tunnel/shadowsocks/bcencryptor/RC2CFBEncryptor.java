package me.smartproxy.tunnel.shadowsocks.bcencryptor;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;

/**
 * Created by hy on 9/26/16.
 */

public class RC2CFBEncryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamCipher createCipher(){
        return new CFBBlockCipher(new RC2Engine(), method.ivLength * 8);
    }
}
