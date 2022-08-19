import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import sun.security.jca.ProviderList;

import java.io.*;
import java.security.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import javax.crypto.Cipher;
import java.time.Duration;
import java.time.Instant;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Main {

    private static final int KEY_SIZE = 128;

    private static final String AES_CIPHER = "AES/CBC/PKCS5PADDING";

    //Translate image into base64
    public static String imageToBase64(String path) throws Exception {
        String base64 = "";
        File file = new File(path);
        FileInputStream image = new FileInputStream(file);
        byte data[] = new byte[(int) file.length()];
        image.read(data);
        base64 = Base64.getEncoder().encodeToString(data);
        return base64;
    }


    public static void AESImageEncryption128CBC() throws Exception {
        String imageFile = imageToBase64("data/1MB.jpg");

        //time starter
        Instant start = Instant.now();

        //key generation part
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey symmetricKey_128 = keyGenerator.generateKey();


        //initialization vector part
        byte[] iv = new byte[16];
        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // define encryption cipher part
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, symmetricKey_128,ivSpec);
        byte[] cipherText = encryptCipher.doFinal(imageFile.getBytes());
        String encrypted_string = Base64.getEncoder().encodeToString(cipherText);
        System.out.println("Initialization Vector for CBC 128: " + Base64.getEncoder().encodeToString(iv));

        // write image
        FileOutputStream fosEncrypt = new FileOutputStream("encrypted/1MB_image_128bitKeyCBC.jpg");
        byte[] imageArray = Base64.getDecoder().decode(encrypted_string);
        fosEncrypt.write(imageArray);
        File fileEncrypt = new File("encrypted/1MB_image_128bitKeyCBC.txt");
        BufferedWriter bw = new BufferedWriter(new FileWriter(fileEncrypt));
        bw.write(encrypted_string);

        //define decryption cipher part
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, symmetricKey_128,ivSpec);
        byte[] plainText = decryptCipher.doFinal(Base64.getDecoder().decode(encrypted_string));
        String decrypted_string = new String(plainText,"utf-8");

        //write image
        FileOutputStream imageOutFile = new FileOutputStream("decrypted/1MB_image_128bitKeyCBC.jpg");
        byte[] decodedImageByteArray = Base64.getDecoder().decode(decrypted_string);
        imageOutFile.write(decodedImageByteArray);


        //timer stop
        Instant finish = Instant.now();
        long elapsedTime = Duration.between(start, finish).toMillis();
        System.out.println("Elapsed time : " + elapsedTime);

    }

    public static void AESImageEncryption256CBC() throws Exception {
        String imageFile = imageToBase64("data/1MB.jpg");

        //time starter
        Instant start = Instant.now();

        //key generation part
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey symmetricKey_256 = keyGenerator.generateKey();


        //initialization vector part
        byte[] iv = new byte[16];
        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        //initialising cipher
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, symmetricKey_256,ivSpec);

        // define encryption cipher part
        byte[] cipherText = encryptCipher.doFinal(imageFile.getBytes());
        String encrypted_string = Base64.getEncoder().encodeToString(cipherText);
        System.out.println("Initialization Vector for CBC 256: " + Base64.getEncoder().encodeToString(iv) );

        // write image
        FileOutputStream fosEncrypt = new FileOutputStream("encrypted/1MB_image_256bitKeyCBC.jpg");
        byte[] imageByteArray = Base64.getDecoder().decode(encrypted_string);
        fosEncrypt.write(imageByteArray);
        File fileEncrypt = new File("encrypted/1MB_image_256bitKeyCBC.txt");
        BufferedWriter bw = new BufferedWriter(new FileWriter(fileEncrypt));
        bw.write(encrypted_string);

        // define decryption cipher part
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, symmetricKey_256,ivSpec);
        byte[] plainText = decryptCipher.doFinal(Base64.getDecoder().decode(encrypted_string));
        String decrypted_string = new String(plainText,"utf-8");

        //write image
        FileOutputStream imageOutFile = new FileOutputStream("decrypted/1MB_image_256bitKeyCBC.jpg");
        byte[] decodedImageByteArray = Base64.getDecoder().decode(decrypted_string);
        imageOutFile.write(decodedImageByteArray);


        //timer stop
        Instant finish = Instant.now();
        long elapsedTime = Duration.between(start, finish).toMillis();
        System.out.println("Elapsed time : " + elapsedTime );

    }

    public static void AESImageEncryption256CTR() throws Exception {

        //time start
        Instant start = Instant.now();


        String imageFile = imageToBase64("data/1MB.jpg");

        //generate key part
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey symmetricKey256 = keyGenerator.generateKey();

        //generate nonce part
        byte [] nonce = new byte[12];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);

        //initialization vector part
        byte[] iv = new byte[16];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        //define encryption cipher part
        Cipher encryptCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, symmetricKey256,ivSpec);
        byte[] cipherText = encryptCipher.doFinal(imageFile.getBytes());
        String encryptedString = Base64.getEncoder().encodeToString(cipherText);
        FileOutputStream imageOutFileEncrpyt = new FileOutputStream("encrypted/1MB_image_256bitKeyCTR.jpg");
        byte[] imageByteArrayEn = Base64.getDecoder().decode(encryptedString);
        imageOutFileEncrpyt.write(imageByteArrayEn);

        //define decryption cipher part
        Cipher decryptCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, symmetricKey256,ivSpec);
        byte[] plainText = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedString));
        String decryptedString = new String(plainText,"utf-8");

        //write image
        FileOutputStream imageOutFileDecrypt = new FileOutputStream("decrypted/1MB_image_256bitKeyCTR.jpg");
        byte[] imageByteArrayDecrypt = Base64.getDecoder().decode(decryptedString);
        imageOutFileDecrypt.write(imageByteArrayDecrypt);

        //stop timer
        Instant finish = Instant.now();
        long elapsedTime = Duration.between(start, finish).toMillis();
        System.out.println("Elapsed time : " + elapsedTime );


    }

    public static void main(String[] args) throws Exception {
        //GenerateECDHKeys();

        //GenerationOfSymmetricKeys();

        AESImageEncryption128CBC();

        AESImageEncryption256CBC();

        AESImageEncryption256CTR();



    }




    // Secret key generation
    public static SecretKey giveAESKey() throws Exception
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    // Fill vector with random values
    public static byte[] giveInitializationVector()
    {
        byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);
        return initializationVector;
    }

    // AES encryption part
    public static byte[] AESEncryption(String text, SecretKey secretKey, byte[] initializationVector)throws Exception
    {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivParameterSpec);
        return cipher.doFinal(text.getBytes());
    }


    static void GenerationOfSymmetricKeys() throws Exception {

        //generate aes key
        SecretKey symmetricKey = giveAESKey();
        System.out.println("Symmetric key size : " + KEY_SIZE);
        System.out.println("Symmetric Key is :" + DatatypeConverter.printHexBinary(symmetricKey.getEncoded()));

        //generate iv
        byte[] initializationVector = giveInitializationVector();

        String plainText = "CSE4057 Spring 2022 Information System Security";

        // Encrypting the message using the symmetric key
        byte[] cipher = AESEncryption(plainText,symmetricKey,initializationVector);

        System.out.println( "Encrypted Message : "+ DatatypeConverter.printHexBinary(cipher));

        // Decrypting the encrypted message
        String decrypted = AESDecryption( cipher,symmetricKey,initializationVector);

        System.out.println("Your original message is: "+ decrypted);
        System.out.print("");
    }


    // AES decryption part
    public static String AESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector)throws Exception
    {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init( Cipher.DECRYPT_MODE,secretKey,ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

    static void GenerateECDHKeys() throws Exception {
        //proper parameter given to functions
        Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        ProviderList.newList(BC);
        ECNamedCurveParameterSpec eCurve = ECNamedCurveTable.getParameterSpec("P-256");
        KeyPairGenerator keyPairGenerator = (KeyPairGenerator) KeyPairGenerator.getInstance("ECDH", BC);
        keyPairGenerator.initialize(eCurve, new SecureRandom());

        //first private key generated
        KeyPair firstKeyPair = keyPairGenerator.generateKeyPair();
        KeyAgreement firstKeyAgree = KeyAgreement.getInstance("ECDH", BC);
        firstKeyAgree.init(firstKeyPair.getPrivate());
        //its pair generated
        KeyPair secondKeyPair = keyPairGenerator.generateKeyPair();
        KeyAgreement secondKeyAgree = KeyAgreement.getInstance("ECDH", BC);
        secondKeyAgree.init(secondKeyPair.getPrivate());
        //generate their public keys
        firstKeyAgree.doPhase(secondKeyPair.getPublic(), true);
        secondKeyAgree.doPhase(firstKeyPair.getPublic(), true);

        byte[] firstSecret = firstKeyAgree.generateSecret();
        byte[] secondSecret = secondKeyAgree.generateSecret();

        System.out.println(new String(firstSecret));
        System.out.println(new String(secondSecret));

        System.out.println("");
    }
}