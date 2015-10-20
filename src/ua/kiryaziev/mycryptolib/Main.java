package ua.kiryaziev.mycryptolib;

import ua.kiryaziev.mycryptolib.cryptomanager.RsaCrypter;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {
    public static void main(String[] args) throws Exception {

        RsaCrypter rsa = new RsaCrypter();

        KeyPair keyPair = rsa.generateKeys(2048);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        rsa.saveKeyToFile("private.der", rsa.marshalPKCS8PrivateDERKey(privateKey));
        rsa.saveKeyToFile("public.der", rsa.marshalX509PublicDERKey(publicKey));

        System.out.println("Done.");

    }
}
