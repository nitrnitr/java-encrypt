package org.mirth.project;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import static org.apache.commons.codec.binary.Base64.encodeBase64;
import static org.apache.commons.codec.binary.Base64.decodeBase64;

public class Crypt {
    public static void main( String[] args )
    {
      /*
        System.out.println("Class loaded!");
        try {
          String key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnBilR5sLqIE8dJjXN03E\nTAA7f/QMFICC1JjbArFWSauITJ/3yf/p3hCus1GJGG7+w+6YS27sNhnp6XIS3Gi0\nx2tf06LvTg6oKyGD7gDwP4C/HIbLbpqgtIumJQKoKuX4Bte4J1X7D4163eHFhAXP\n+v568D5TWh0Y5t9Wmlvtvla0nS2VaK8/moawjUs3MvSCt9EyEKZwnHoBX8WGhLFz\nMDsYV64DlMjkRGeKNLoHdFqQA/0so/JXEmE770XaHMsCcugXBxs9ZqfzsQDntuns\nfq48wLtsX+hZRGFHD4dLdgJ9aUxMkXfPeuMhoEY89GWP9tsgkwcRkRdccYDR42rI\n3QIDAQAB\n-----END PUBLIC KEY-----\n";
          String content = "Some long aslsa jqrjq nqwr jqwrq nqw wq rwq rwqr qrq qw wq r qrwong long long long long long long long long jajajajasdjkansqwrq long content jasdjasjasjasda nsd asdnqwrj qwrjk qkwjr kqwr lqkjr lkqj rlkqrjlkjrlkqwjrlqwk j   lkqjrlqwkj";
          content += "Some long aslsa jqrjq nqwr jqwrq nqw wq rwq rwqr qrq qw wq r qrwong long long long long long long long long jajajajasdjkansqwrq long content jasdjasjasjasda nsd asdnqwrj qwrjk qkwjr kqwr lqkjr lkqj rlkqrjlkjrlkqwjrlqwk j   lkqjrlqwkj";
          content += "Some long aslsa jqrjq nqwr jqwrq nqw wq rwq rwqr qrq qw wq r qrwong long long long long long long long long jajajajasdjkansqwrq long content jasdjasjasjasda nsd asdnqwrj qwrjk qkwjr kqwr lqkjr lkqj rlkqrjlkjrlkqwjrlqwk j   lkqjrlqwkj";
          content += "Some long aslsa jqrjq nqwr jqwrq nqw wq rwq rwqr qrq qw wq r qrwong long long long long long long long long jajajajasdjkansqwrq long content jasdjasjasjasda nsd asdnqwrj qwrjk qkwjr kqwr lqkjr lkqj rlkqrjlkjrlkqwjrlqwk j   lkqjrlqwkj";
          content += "Some long aslsa jqrjq nqwr jqwrq nqw wq rwq rwqr qrq qw wq r qrwong long long long long long long long long jajajajasdjkansqwrq long content jasdjasjasjasda nsd asdnqwrj qwrjk qkwjr kqwr lqkjr lkqj rlkqrjlkjrlkqwjrlqwk j   lkqjrlqwkj";
          String res = encrypt(key, content);
          System.out.println("res " + res);
        } catch(Exception e) {
          System.out.println(e);
        }
        */
    }

    public static String encrypt(String rawKey, String inputData)
        throws Exception {

        String cleanKey = stripKey(rawKey);
        byte[] publicKey = decodeBase64(cleanKey);

        PublicKey key = KeyFactory.getInstance("RSA")
                                  .generatePublic(new X509EncodedKeySpec(publicKey));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Need to encode it in chunks
        ByteArrayInputStream in = new ByteArrayInputStream (inputData.getBytes("utf-8"));
        byte[] buffer = new byte[244];
        int len;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while ((len = in.read(buffer)) > 0) {
          byte[] thisChunk = cipher.doFinal(buffer);
          output.write(thisChunk);
        }
        byte[] out = output.toByteArray();
        byte[] encoded = Base64.getEncoder().encode(out);
        String res = new String(encoded);
        return res;
    }

    private static String stripKey(String key) {
      String stripped = key.replace("-----BEGIN PUBLIC KEY-----", "")
                           .replaceAll(System.lineSeparator(), "")
                           .replace("-----END PUBLIC KEY-----", "");

      return stripped;
    }
}
