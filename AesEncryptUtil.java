package com.digitalchina.frame.encrypt;

import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author shentt
 * @date 2018年4月27日
 * @className AesEncryptUtil.java
 * @param 
 * @Description java与js相互加密解密的对称加密算法AES工具
 */
public class AesEncryptUtil {
	
	//使用AES-128-CBC加密模式，key需要为16位,key和iv可以相同！
	public static String KEY = "1234123412ABCDEF";
	
	public static String IV = "ABCDEF1234123412";
	
	
	/**
	 * 加密方法
	 * @param data  要加密的数据
	 * @param key 加密key
	 * @param iv 加密iv
	 * @return 加密的结果
	 * @throws Exception
	 */
	public static String encrypt(String data, String key, String iv) throws Exception {
		try {

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");//"算法/模式/补码方式"
			int blockSize = cipher.getBlockSize();

			byte[] dataBytes = data.getBytes("utf-8");
			int plaintextLength = dataBytes.length;
			if (plaintextLength % blockSize != 0) {
				plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
			}

			byte[] plaintext = new byte[plaintextLength];
			System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);

			SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
			IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());

			cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
			byte[] encrypted = cipher.doFinal(plaintext);

			return new Base64().encodeToString(encrypted);

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 解密方法
	 * @param data 要解密的数据
	 * @param key  解密key
	 * @param iv 解密iv
	 * @return 解密的结果
	 * @throws Exception
	 */
	public static String desEncrypt(String data, String key, String iv) throws Exception {
		try {
			byte[] encrypted1 = new Base64().decode(data);

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
			IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());

			cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);

			byte[] original = cipher.doFinal(encrypted1);
			String originalString = new String(original,"utf-8");
			return originalString;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 使用默认的key和iv加密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String data) throws Exception {
		return encrypt(data, KEY, IV);
	}
	
	/**
	 * 使用默认的key和iv解密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String desEncrypt(String data) throws Exception {
		return desEncrypt(data, KEY, IV);
	}
	
	public static String readString(String file_address)
    {
        int len=0;
        StringBuffer str=new StringBuffer("");
        File file=new File(file_address);
        try {
            FileInputStream is=new FileInputStream(file);
            InputStreamReader isr= new InputStreamReader(is);
            BufferedReader in= new BufferedReader(isr);
            String line=null;
            while( (line=in.readLine())!=null )
            {
                if(len != 0)  // 处理换行符的问题
                {
                    str.append("\r\n"+line);
                }
                else
                {
                    str.append(line);
                }
                len++;
            }
            in.close();
            is.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return str.toString();
    }
	
	
	/**
	* 测试
	*/
	public static void main(String args[]) throws Exception {
		String test = "我";

		String data = null;
//		String key = "dufy20170329java";
//		String iv = "dufy20170329java";

		data = encrypt(test);

		System.out.println(data);
		System.out.println(desEncrypt("QE4g0p1qoZynf8gBHUC+cTDc7iYV8uMgSkvuX99Hh54=", KEY, IV));
		System.out.println(desEncrypt(data, KEY, IV));
		
//		System.out.println(test.equals(desEncrypt(data, KEY, IV)));
	}
	
}