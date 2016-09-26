package me.smartproxy.tunnel.shadowsocks;


public class EncryptorFactory {
	
	public static ShadowsocksEncryptor createEncryptorByConfig(ShadowsocksConfig config) throws Exception{
		EncryptMethod encryptMethod = EncryptMethod.parseMethod(config.EncryptMethod);

		if (encryptMethod == null) {
			throw new Exception(String.format("Does not support the '%s' method. Only 'table' encrypt method was supported.", config.EncryptMethod));
		}else {
			return encryptMethod.createEncryptor(config.Password);
		}
	}
}
