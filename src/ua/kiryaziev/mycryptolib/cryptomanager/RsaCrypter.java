package ua.kiryaziev.mycryptolib.cryptomanager;

import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaCrypter {

    // ============================
    // generateKeys
    // ============================
    public KeyPair generateKeys(int keySize) throws  Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    // ============================
    // marshalPKCS8PrivateDERKey
    // ============================
    public String marshalPKCS8PrivateDERKey(PrivateKey privateKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        return Base64.getEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded());
    }

    // ============================
    // marshalX509PublicDERKey
    // ============================
    public String marshalX509PublicDERKey(PublicKey publicKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        return Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded());
    }

    // ============================
    // saveKeyToFile
    // ============================
    public void saveKeyToFile(String filename, String key) throws Exception {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(key.getBytes("UTF-8"));
        fos.close();
    }

    // ============================
    // parsePKCS8PrivatePEMKey
    // ============================
    public PrivateKey parsePKCS8PrivatePEMKey(String pemKey) throws Exception {
        String decoded = pemKey.
                replace("-----BEGIN RSA PRIVATE KEY-----\n", "").
                replace("-----END RSA PRIVATE KEY-----", "").
                replace("\r", "").
                replace("\n", "").
                replace(" ", "");
        byte[] encoded = Base64.getDecoder().decode(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    // ============================
    // parsePKCS8PrivateDERKey
    // ============================
    public PrivateKey parsePKCS8PrivateDERKey(String derKey) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(derKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    // ============================
    // parseX509PublicPEMKey
    // ============================
    public PublicKey parseX509PublicPEMKey(String pemKey) throws Exception {
        String decoded = pemKey.
                replace("-----BEGIN PUBLIC KEY-----\n", "").
                replace("-----END PUBLIC KEY-----", "").
                replace("\r", "").
                replace("\n", "").
                replace(" ", "");
        byte[] encoded = Base64.getDecoder().decode(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    // ============================
    // parseX509PublicDERKey
    // ============================
    public PublicKey parseX509PublicDERKey(String derKey) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(derKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    /**
     * Encrypte PKCS1
     * @param publicKey RSA public key
     * @param message Source message
     * @return Encrypted message
     * @throws Exception
     */
    public String encryptPKCS1(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")));
    }

    /**
     * Decrypt PKCS1
     * @param privateKey RSA private key
     * @param encryptedMessage Encrypted message
     * @return Decrypted message
     * @throws Exception
     */
    public String decryptPKCS1(PrivateKey privateKey, String encryptedMessage) throws Exception {
        String cleared_message = encryptedMessage.
                replace("\n", "").
                replace("\r", "").
                replace(" ", "");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cleared_message)), "UTF-8");
    }
}
