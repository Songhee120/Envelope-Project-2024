package com.webcode.detectiveclub.service;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Data
@org.springframework.stereotype.Service
public class Service {

    final static String keyAlgorithm = "RSA";
    final static String secretKeyAlgorithm = "AES";
    final static String hashAlgorithm = "SHA-1";

    final static String pubType = ".publickey";
    final static String priType = ".privatekey";
    final static String secretType = ".secretkey";

    final static String sigType = ".sigature";
    final static String msgType = ".message";
    final static String envType = ".envelope";

    final static String keyPath = "src/main/resources/keys/";
    final static String prePath = "src/main/resources/envelope/prepare/";
    final static String resultPath = "src/main/resources/envelope/result/";

    private String message;
    private String sender;
    private String receiver;

    public List<String> getUsers() {
        return Arrays.asList("예나", "재재", "도연", "지윤", "비비");
    }


    public void generateKeyPair(String name) {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();

        try(FileOutputStream priFos = new FileOutputStream(keyPath + name + priType);
            FileOutputStream pubFos = new FileOutputStream(keyPath + name + pubType);
            ObjectOutputStream priOos = new ObjectOutputStream(priFos);
            ObjectOutputStream pubOos = new ObjectOutputStream(pubFos);
        ) {
            priOos.writeObject(key.getPrivate());
            pubOos.writeObject(key.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generateSecretKey(String name) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(secretKeyAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGen.init(128);
        Key secretKey = keyGen.generateKey();

        try(FileOutputStream fos = new FileOutputStream(keyPath + name + secretType);
            ObjectOutputStream oos = new ObjectOutputStream(fos);) {
            oos.writeObject(secretKey);
        }  catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getHashValue(String message) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        messageDigest.update(message.getBytes());
        return messageDigest.digest();
    }

    public void generateSignature(byte[] hashValue) {
        // 암호화 준비
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(keyAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, getKey(sender, priType));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        String filePath = prePath + sender + sigType;
        encrypt(cipher, hashValue, filePath);
    }

    // 메세지, 서명, 공개키를 수신자의 비밀키로 암호화
    public void encryptWithPrivateKey() {
        Key secretKey = getKey(sender, secretType);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(secretKeyAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        // 메세지
        encrypt(cipher, message.getBytes(), resultPath + sender + msgType);

        // 서명
        byte[] signature;
        try(FileInputStream fis = new FileInputStream(prePath + sender + sigType)) {
            signature = fis.readAllBytes();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        encrypt(cipher, signature, resultPath + sender + sigType);

        // 공개키
        encrypt(cipher, getKey(receiver, pubType).getEncoded(), resultPath + sender + pubType);
    }

    public void generateEnvelope() {
        Key secretKey = getKey(sender, secretType);
        Key pubKey = getKey(receiver, pubType);

        // 암호화
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(keyAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        encrypt(cipher, secretKey.getEncoded(), resultPath + sender + envType);

    }


    public String decryptAllAndGetMessage() {
        // 송신자의 비밀키 복호화 (수신자의 개인키로)
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(keyAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, getKey(receiver, priType));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        byte[] data = decrypt(cipher, resultPath + sender + envType);
        log.info(Arrays.toString(data));

        // 메세지, 전자서명, 송신자 공개키 복호화 (송신자의 비밀키로)

        return null;
    }

    private Key getKey(String owner, String keyType) {
        Key key = null;
        String path = keyPath + owner + keyType;
        try(FileInputStream fis = new FileInputStream(path);
            ObjectInputStream ois = new ObjectInputStream(fis);) {
            key = (Key) ois.readObject();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        return key;
    }

    private void encrypt(Cipher cipher, byte[] data, String filePath) {
        try(FileOutputStream fos = new FileOutputStream(filePath);
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);) {
            cos.write(data);
            cos.flush();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] decrypt(Cipher cipher, String filePath) {
        try(FileInputStream fis = new FileInputStream(filePath);
            CipherInputStream cis = new CipherInputStream(fis, cipher);) {
            return cis.readAllBytes();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}