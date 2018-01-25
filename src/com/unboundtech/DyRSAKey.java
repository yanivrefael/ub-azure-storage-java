package com.unboundtech;

import com.dyadicsec.provider.RSAPrivateKey;
import com.microsoft.azure.keyvault.core.IKey;
import com.microsoft.azure.keyvault.extensions.RsaKey;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.concurrent.Future;

public class DyRSAKey implements IKey {

    private RsaKey rsaKey;
    private String keyName;

    public DyRSAKey(String keyName) {
        this.keyName = keyName;
    }

    public void load() throws GeneralSecurityException , IOException{

        KeyStore keyStore = KeyStore.getInstance("PKCS11", "DYADIC");
        keyStore.load(null);
        PrivateKey rsaPrivateKey = (PrivateKey) keyStore.getKey(keyName,null);
        if(rsaPrivateKey == null){
            throw new UnrecoverableKeyException(String.format("Key %s not found",keyName));
        }
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(
                new RSAPublicKeySpec(((RSAPrivateKey) rsaPrivateKey).getModulus(), ((RSAPrivateKey) rsaPrivateKey).getPublicExponent()));
        KeyPair rsaKeyPair = new KeyPair(rsaPublicKey,rsaPrivateKey);
        this.rsaKey = new RsaKey(keyName,rsaKeyPair);
    }

    @Override
    public String getDefaultEncryptionAlgorithm() {
        return rsaKey.getDefaultEncryptionAlgorithm();
    }

    @Override
    public String getDefaultKeyWrapAlgorithm() {
        return rsaKey.getDefaultKeyWrapAlgorithm();
    }

    @Override
    public String getDefaultSignatureAlgorithm() {
        return rsaKey.getDefaultSignatureAlgorithm();
    }

    @Override
    public String getKid() {
        return keyName;
    }

    @Override
    public Future<byte[]> decryptAsync(byte[] ciphertext, byte[] iv, byte[] authenticationData, byte[] authenticationTag, String algorithm)
            throws NoSuchAlgorithmException {
        return rsaKey.decryptAsync(ciphertext,iv,authenticationData,authenticationTag,algorithm);
    }

    @Override
    public Future<Triple<byte[], byte[], String>> encryptAsync(byte[] plaintext, byte[] iv, byte[] authenticationData, String algorithm) throws NoSuchAlgorithmException {
        return rsaKey.encryptAsync(plaintext,iv,authenticationData,algorithm);
    }

    @Override
    public Future<Pair<byte[], String>> wrapKeyAsync(byte[] key, String algorithm) throws NoSuchAlgorithmException {
        return rsaKey.wrapKeyAsync(key,algorithm);
    }

    @Override
    public Future<byte[]> unwrapKeyAsync(byte[] encryptedKey, String algorithm) throws NoSuchAlgorithmException {
        return rsaKey.unwrapKeyAsync(encryptedKey,algorithm);
    }

    @Override
    public Future<Pair<byte[], String>> signAsync(byte[] digest, String algorithm) {
        return rsaKey.signAsync(digest,algorithm);
    }

    @Override
    public Future<Boolean> verifyAsync(byte[] digest, byte[] signature, String algorithm) {
        return rsaKey.verifyAsync(digest,signature,algorithm);
    }

    @Override
    public void close() throws IOException {

    }
}



