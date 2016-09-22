package me.smartproxy.tunnel.shadowsocks;

import java.util.HashMap;

import me.smartproxy.tunnel.IEncryptor;

public class EncryptorFactory {
	
	private static HashMap<String, IEncryptor> EncryptorCache = new HashMap<String, IEncryptor>();
 
	public static AbstractEncryptor createEncryptorByConfig(ShadowsocksConfig config) throws Exception{
		EncryptMethod encryptMethod = EncryptMethod.parseMethod(config.EncryptMethod);

		if (encryptMethod == null) {
			throw new Exception(String.format("Does not support the '%s' method. Only 'table' encrypt method was supported.", config.EncryptMethod));
		}else {
			return encryptMethod.createEncryptor(config.Password);
		}
	}
}
