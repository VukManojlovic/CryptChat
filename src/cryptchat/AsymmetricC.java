/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptchat;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Vuk
 */
public class AsymmetricC {

    private static final String RSA = "RSA";
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricC() {
        
    }
    
    public void createNewKeys(){
        KeyPair kp = this.generateNewKeyPair();
        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
    }

    private KeyPair generateNewKeyPair() {
        try {
            SecureRandom sr = new SecureRandom();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(2048, sr);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public String encryptRSA(String plain, String publicKeyHex) {
        try {
            PublicKey pk = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(this.hex2bytes(publicKeyHex)));
            Cipher c = Cipher.getInstance(RSA);
            c.init(Cipher.ENCRYPT_MODE, pk);
            byte[] bytes = c.doFinal(plain.getBytes());
            return Hex.toHexString(bytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public String sign(String plain){
        try {
            Signature privateSignature = Signature.getInstance("SHA1withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(plain.getBytes());
            byte[] signed = privateSignature.sign();
            return Hex.toHexString(signed);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    public String encryptMessage(String plain, String publicKeyHex){
        SymmetricC symmetric = new SymmetricC();
        symmetric.createNewKey();
        String cipherText = symmetric.encryptMessage(plain);
        String encodedKey = encryptRSA(symmetric.getKeyHex(), publicKeyHex);
        String signed = this.sign(symmetric.getKeyHex());
        return encodedKey + "-" + signed + "-" + cipherText;
    }
    
    public String decryptRSA(String cipher) {
        try {
            Cipher c = Cipher.getInstance(RSA);
            c.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] decoded = c.doFinal(this.hex2bytes(cipher));
            return new String(decoded);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException  ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public boolean verify(String key, String signature, String publicKeyHex) {
        try {
            PublicKey pk = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(this.hex2bytes(publicKeyHex)));
            Signature publicSignature =  Signature.getInstance("SHA1withRSA");
            publicSignature.initVerify(pk);
            publicSignature.update(key.getBytes());
            return publicSignature.verify(this.hex2bytes(signature));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }
    
    public String[] decryptMessage(String cipher, String publicKeyHex){
        StringTokenizer st = new StringTokenizer(cipher, "-");
        String key = decryptRSA(st.nextToken());
        String signature = st.nextToken();
        boolean verified = this.verify(key, signature, publicKeyHex);
        SymmetricC symmetric = new SymmetricC(key);
        String message = symmetric.decryptMessage(st.nextToken());
        String[] MessageVerify = new String[2];
        MessageVerify[0] = message;
        if(verified){
            MessageVerify[1]="true";
        }else{
            MessageVerify[1]="false";
        }
        return MessageVerify;
    }

    public String getPublicKeyHex() {
        String keyHex = Hex.toHexString(this.publicKey.getEncoded());
        return keyHex;
    }

    public byte[] getPublicBytes() {
        return this.publicKey.getEncoded();
    }
    
    public String bytes2hex(byte[] bytes){
        return Hex.toHexString(bytes);
    }
    public byte[] hex2bytes(String hex){
        return Hex.decode(hex);
    }
}