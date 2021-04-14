package com.javacircle.encription;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Key;
import java.util.Base64;

public class AESEncrypter {

    private static  final String ALGO = "AES";
    private byte[] keyValue;

    public AESEncrypter(String key){
        keyValue = key.getBytes();
    }

    public String encrypt(String data) throws Exception {
        Key key =generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());

        Base64.Encoder encoder = Base64.getEncoder();

//        String normalString = "username:password";
//        String encodedString = encoder.encodeToString(
//                normalString.getBytes(StandardCharsets.UTF_8) );
        String encryptedValue =  encoder.encode(encVal).toString();
//        String encryptedValue = new BAS .encode(encVal);

          return encryptedValue;
    }


    public String decrypt(String encryptionData)  throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);


        //String encodedString = "dXNlcm5hbWU6cGFzc3dvcmQ=";
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decordedValue = decoder.decode(encryptionData);

        //byte[] decordedValue = new Base64decoder().decodeBuffer(encryptionData);


        byte[] deValue = c.doFinal(decordedValue);

        String  decryptedValue = new String(deValue);
        return decryptedValue;
    }

    private Key generateKey(){
        Key key = new SecretKeySpec(keyValue, ALGO);
        return  key;
    }

    public static void main(String args[]){
        try{
            AESEncrypter aESEncrypter = new AESEncrypter("Iv39eptlvuhaqqsr");
            String encData = aESEncrypter.encrypt("Slemhhhhhh");
            System.out.println("Encrypt " +  encData);
            String decData = aESEncrypter.decrypt(encData);
            System.out.println("decrypt " +  decData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
