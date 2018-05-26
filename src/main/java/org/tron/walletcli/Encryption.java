package org.tron.walletcli;

import io.netty.handler.codec.base64.Base64Decoder;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.spongycastle.util.encoders.Hex;
import org.tron.common.utils.ByteUtil;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
    private String key = new String();
    String IV =  "abcdefgh";

    public Encryption(String key){
        this.key = key;
    }

    public String encryptText(String data){
        String res = new String();
        if (data != null && !data.trim().equals("")){
            System.out.println("not empty | Data: " + StringEscapeUtils.escapeJava(data));
            System.out.println("key byte length: " + key.getBytes().length);
            System.out.println("data byte length: " + data.getBytes().length);
            try{
                SecretKeySpec sk = new SecretKeySpec(key.getBytes(), "Blowfish");
                Cipher sk_cphr = Cipher.getInstance("Blowfish");
                sk_cphr.init(Cipher.ENCRYPT_MODE, sk);

                byte[] byte_res = sk_cphr.doFinal(data.getBytes("UTF-8"));
                res = ByteUtil.toHexString(byte_res);
            }catch(Exception e){
                e.printStackTrace();
                res = new String();
            }
            System.out.println("enc res: " + res);
        }
        return res;
    }

    public String decryptText(String data){
        String res = new String();
        if (data != null && !data.trim().equals("")) {
            System.out.println("D not empty | Data: " + StringEscapeUtils.escapeJava(data));
            System.out.println("D key byte length: " + key.getBytes().length);
            System.out.println("D data byte length: " + data.getBytes().length);

            data = data.trim();
            try {
                byte[] hex_bytes = Hex.decode(data);
                SecretKeySpec sk = new SecretKeySpec(key.getBytes(), "Blowfish");
                Cipher sk_cphr = Cipher.getInstance("Blowfish");
                sk_cphr.init(Cipher.DECRYPT_MODE, sk);
                res = new String(sk_cphr.doFinal(hex_bytes), "iso-8859-1");

            } catch (Exception e) {
                e.printStackTrace();
                res = new String();
            }

        }
        System.out.println("return decryptiong: " + res);
        return res;
    }


    public String encryptObject(JSONObject json_obj){
        String json_str = json_obj.toJSONString();
        String enc = encryptText(json_str);
        return enc;
    }

    public JSONObject decryptObject(String json_obj){
        JSONParser parser = new JSONParser();
        JSONObject res_obj;
        try{
            res_obj = (JSONObject) parser.parse(decryptText(json_obj));
        }catch (Exception e){
            res_obj = new JSONObject();
        }
        return res_obj;
    }
}
