package com.javacircle.learning.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {

    public static void main(String args[]){

        byte[] num = CryptoUtils.getRandomNonce16Bytes();
        System.out.println(Arrays.toString(num) );

        try {
            char[] password = {3,4,23,4,6,7,8,8};
            byte[] bit = {1,3,56,7,9,4};
            System.out.println(CryptoUtils.hexWithBlockSize(bit, 21));

            System.out.println(" secret Key " + Arrays.toString(CryptoUtils.getAESKeyFromPassword(password,bit ).getEncoded()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }


}
