package com.encrpytionDecrpytion.gpgalgorithm;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.crypto.Cipher;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SpringBootApplication

public class GpgalgorithmApplication {

  static String encryptedString = null;
  static JcaPGPPublicKeyRingCollection pgpPub;
  static PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
  static String pubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    + "\n"
    + "mQERBGLiUHcBCCCxzKzOL9Rjw735ZU6TV8nzj4BIXLcNRPcGE45imUnJP43KH/nr\n"
    + "afngRwQ1NBpDA1Rhcogr6Jr8EM0CelixZ3AVpXWmDHPCJCjRCgtDy007L53nA7jD\n"
    + "ksH9ZqvXFxIvBMjkT8kCs/67fL0x1BmfraBAqQz0B+6uP/7F9N5UJPpxNssBRPV6\n"
    + "UwjozXymLuWFenCAsspAK0roVjeOBbu7CcmlGMVUyzW33LKuHLDznqTHsmYxvlh7\n"
    + "crtDj/uGEFAx4kTGrIi/B52FmHGCWN4fwX+VgewtgxA6jpppIGl70PBv37Y+gVq5\n"
    + "2/zuE+VR8q3UlhIw/Z74suN2w6RGrnSRRSXfNby/kQARAQABtCtqYXlyYXRob2Qg\n"
    + "KGpheXJhdGhvZCkgPGpheXJhdGhvZEBnbWFpbC5jb20+iQFSBBMBCAA4FiEEZtAf\n"
    + "A1dEY/6B+guK6ELNQRhjVBoFAmLiUHcCGw0FCwkIBwIGFQoJCAsCBBYCAwECHgEC\n"
    + "F4AACgkQ6ELNQRhjVBqklQgeMWIVAh70gqq5NtjKXycQzwpXGa3RezBREOaSR18T\n"
    + "VxkiNIPLBnnNtTHs5uUgtWQmXTdHgfHKrGBdvp44NXaSGOjv1I2DB18zihZ2WnY8\n"
    + "A84JvBl2ESLdyoYVaQbktGBs8Z0ckkMf/9L53nN+218jeYjuu8pilFpiNDTzmjpl\n"
    + "zL71FtHTDkwB1DQpCZYKMgFC7IaVr/SJRBY2klV9lTvzNLk9EFKUm5+mP+qzGve2\n"
    + "E5KSDX7XJ9W3LoJ5MZc6c3afJawS1PRy5VZ2j7UlAa5OcmHpol6E9mtf+DLxLse7\n"
    + "OhWVfy2pjLKajnJxaQyKkg7BfRlLuyL3lUEScUUsMF/+Gt2eBEU=\n"
    + "=0jYv\n"
    + "-----END PGP PUBLIC KEY BLOCK-----\n";
  static InputStream pubKeyInputStream = new ByteArrayInputStream(pubKey.getBytes());

  static String pvtKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    + "\n"
    + "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\n"
    + "ipIOwX0ZS7si95VBEnFFLDBf/hrdngRF\n"
    + "=cD5l\n"
    + "-----END PGP PRIVATE KEY BLOCK-----\n";

  static InputStream pvtKeyInputStream = new ByteArrayInputStream(pvtKey.getBytes());

  //----------------------------------The testing phase----------------------------------

  public static void writeFileToLiteralData(OutputStream out,
    char fileType, File file, byte[] buffer) throws IOException {
    PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
    OutputStream pOut = lData.open(out, fileType, file.getName(),
      new Date(file.lastModified()), buffer);
    FileInputStream in = new FileInputStream(file);
    byte[] buf = new byte[buffer.length];
    int len;

    while ((len = in.read(buf)) > 0) {
      pOut.write(buf, 0, len);
    }

    lData.close();
    in.close();
  }

  //--------------------------------End of the testing methods---------------------------------

  //---------------------------------method to get public key---------------------------------
  public static PublicKey getPublicKey(String publicKeyringFile) throws IOException, PGPException {
    PGPPublicKey pgpPublicKey = null;
    // Read in from the public keyring file
    try (FileInputStream keyInputStream = new FileInputStream(publicKeyringFile)) {
      // Form the PublicKeyRing collection (1.53 way with fingerprint calculator)
      InputStream encodedKey = new ByteArrayInputStream(keyInputStream.readAllBytes());
      InputStream decodedKey = PGPUtil.getDecoderStream(encodedKey);
      PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new JcaPGPPublicKeyRingCollection(decodedKey);
      // Iterate over all public keyrings
      Iterator<PGPPublicKeyRing> iter = pgpPublicKeyRingCollection.getKeyRings();
      PGPPublicKeyRing keyRing;

      while (iter.hasNext()) {
        keyRing = iter.next();
        // Iterate over each public key in this keyring
        Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
        while (keyIter.hasNext()) {
          PGPPublicKey publicKey = keyIter.next();
          // Iterate over each userId attached to the public key
          if (publicKey.isEncryptionKey()) {
            pgpPublicKey = publicKey;
          }
        }

      }
    }
    // If this point is reached, no public key could be extracted
//    PGPPrivateKey pgpPrivateKey=pgpPrivateKeyStream.findAny().orElseThrow();
    JcaPGPKeyConverter jcaPGPKeyConverter=new JcaPGPKeyConverter();
    PublicKey pub = jcaPGPKeyConverter.getPublicKey(pgpPublicKey);
    return pub;
  }

  //---------------------------------method to get private key---------------------------------
  private static PrivateKey getPrivateKey(String privateKey) throws PGPException, IOException {
    InputStream privateKeyInputStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(privateKey.getBytes(
      StandardCharsets.UTF_8)));
    PGPSecretKeyRingCollection pgpSecretKeyRingCollection =
      new PGPSecretKeyRingCollection(privateKeyInputStream, new JcaKeyFingerprintCalculator());
    Iterator<PGPSecretKeyRing> keyRingsItr = pgpSecretKeyRingCollection.getKeyRings();
    PBESecretKeyDecryptor decryptorFactory = new BcPBESecretKeyDecryptorBuilder(
      new BcPGPDigestCalculatorProvider()).build("jayrathod".toCharArray());
    Stream<PGPPrivateKey> pgpPrivateKeyStream = StreamSupport.stream(
        Spliterators.spliteratorUnknownSize(
          keyRingsItr,
          Spliterator.ORDERED)
        , false)
      .map(PGPSecretKeyRing::getSecretKey)
      .map(i -> {
        try {
          return i.extractPrivateKey(decryptorFactory);
        } catch (PGPException e) {
          e.printStackTrace();
          return null;
        }
      });


    PGPPrivateKey pgpPrivateKey=pgpPrivateKeyStream.findAny().orElseThrow();
    JcaPGPKeyConverter jcaPGPKeyConverter=new JcaPGPKeyConverter();
    PrivateKey pri = jcaPGPKeyConverter.getPrivateKey(pgpPrivateKey);
    return pri;
  }

  private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, String passPhrase)
    throws PGPException {

    PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
    if (pgpSecKey == null) {
      return null;
    }
    return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
      .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passPhrase.toCharArray()));
  }

  public static PGPSecretKey getSecretKey(String privateKeyringFile) throws IOException, PGPException {
    PGPSecretKey pgpPrivateKey = null;
    // Read in from the public keyring file
    try (FileInputStream keyInputStream = new FileInputStream(privateKeyringFile)) {
      // Form the PublicKeyRing collection (1.53 way with fingerprint calculator)
      InputStream encodedKey = new ByteArrayInputStream(keyInputStream.readAllBytes());
      InputStream decodedKey = PGPUtil.getDecoderStream(encodedKey);
      PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new JcaPGPSecretKeyRingCollection(decodedKey);//instead of pgppublickeyringcollection sed pgpsecretkeyringcollection
      // Iterate over all public keyrings
      Iterator<PGPSecretKeyRing> iter = pgpSecretKeyRingCollection.getKeyRings();
      PGPSecretKeyRing keyRing;

      while (iter.hasNext()) {
        keyRing = iter.next();
        // Iterate over each public key in this keyring
        Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
        while (keyIter.hasNext()) {
          PGPSecretKey privateKey = keyIter.next();
          // Iterate over each userId attached to the public key
          if (!privateKey.isPrivateKeyEmpty()) {
            pgpPrivateKey = privateKey;
          }
        }

      }
    }
    // If this point is reached, no public key could be extracted
    return pgpPrivateKey;
  }

  //---------------------------------method to encrypt our plain text---------------------------------
  public static String getEncryptedMessage(String strData, PGPPublicKey publicKey) {
    byte[] data = strData.getBytes(StandardCharsets.UTF_8);
    Security.addProvider(new BouncyCastleProvider());
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      OutputStream out = new ArmoredOutputStream(baos);
           /* PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PublicKeyAlgorithmTags.RSA_ENCRYPT).setWithIntegrityPacket(true)
                    .setSecureRandom(new SecureRandom()).setProvider("BC"));*/

      PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
        new BcPGPDataEncryptorBuilder(PublicKeyAlgorithmTags.RSA_ENCRYPT));
      //            BcPublicKeyKeyEncryptionMethodGenerator bcKey = new BcPublicKeyKeyEncryptionMethodGenerator(
//                publicKey);
//            encGen.addMethod(bcKey);
//            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));
      //encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
      encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
      OutputStream cOut = encGen.open(out, data.length);
      cOut.write(data);
      baos.writeTo(cOut);
      baos.toByteArray();
      cOut.close();
      out.close();
      baos.flush();
      encryptedString = new String(baos.toByteArray(), StandardCharsets.UTF_8);
      return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    } catch (PGPException | IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  private static byte[] getPlainTextFromEncrpytedMessage(byte[] pgpEncryptedData, String passphrase) throws Exception {
    PrivateKey privateKey = getPrivateKey(pvtKey);
    PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);
    PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
// note: we can only do this because we know we match the first encrypted data object
    PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
    PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
      .setProvider("BC").build(getPrivateKey(pvtKey));
    InputStream clear = encData.getDataStream(dataDecryptorFactory);
    byte[] literalData = Streams.readAll(clear);
    if (encData.verify()) {
      PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
      PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
      byte[] data = Streams.readAll(litData.getInputStream());
      return data;
    }
//        throw new IllegalStateException("modification check failed");

    return null;
  }

  private static String encode(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }

//  private static String encrypt(String message) throws Exception{
//    byte[] messageToBytes = message.getBytes();
//    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//    cipher.init(Cipher.ENCRYPT_MODE, (Key) getPublicKey("C:\\Users\\jay\\Desktop\\gpgalgorithm\\publickey.asc"));
//    byte[] encryptedBytes = cipher.doFinal(messageToBytes);
//    System.out.println("Encrypted bytes:"+encode(encryptedBytes));
//    return encode(encryptedBytes);
//  }



/*
package com.presedential.title;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import javax.crypto.Cipher;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
public class RSA {
  private PrivateKey privateKey;
  private PublicKey publicKey;
  public RSA() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(1024);
      KeyPair pair = generator.generateKeyPair();
      privateKey = pair.getPrivate();
      publicKey = pair.getPublic();
    } catch (Exception ignored) {
    }
  }
  public String encrypt(String message) throws Exception{
    byte[] messageToBytes = message.getBytes();
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE,publicKey);
    byte[] encryptedBytes = cipher.doFinal(messageToBytes);
    return encode(encryptedBytes);
  }
  private String encode(byte[] data){
    return Base64.getEncoder().encodeToString(data);
  }
  public String decrypt(String encryptedMessage) throws Exception{
    byte[] encryptedBytes = decode(encryptedMessage);
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE,privateKey);
    byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
    return new String(decryptedMessage,"UTF8");
  }
  private byte[] decode(String data){
    return Base64.getDecoder().decode(data);
  }
  public static void main(String[] args) throws Exception {
    RSA rsa = new RSA();
    encrypt();
    decrypt();
   */
/* try{
      String encryptedMessage = rsa.encrypt("This is Linuxhint.com");
      String decryptedMessage = rsa.decrypt(encryptedMessage);
      System.err.println("Encrypted:\n"+encryptedMessage);
      System.err.println("Decrypted:\n"+decryptedMessage);
    }catch (Exception ignored){}
  }*//*
  }
  public static void encrypt() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    //Load Public Key File
    FileInputStream key = new FileInputStream("C:\\Presidential\\0x6243E647-pub.asc");
    //PGPPublicKey pubKey2 = KeyBasedFileProcessorUtil.readPublicKey(key3);
    PGPPublicKey pubKey = KeyBasedFileProcessorUtil.readPublicKey(key);
    //Output file
    FileOutputStream out = new FileOutputStream("C:\\Presidential\\enc.bpg");
    //Input file
    String inputFilename = "C:\\Presidential\\a.txt";
    //Other settings
    boolean armor = false;
    boolean integrityCheck = false;
    KeyBasedFileProcessorUtil.encryptFile(out, inputFilename,
      pubKey, armor, integrityCheck);
  }
  public static void decrypt() throws  Exception
  {
    char a[]={'d','i','g','v','i','j','a','y'};
    String inputFilename2="C:\\Presidential\\enc.bpg";
    FileInputStream key3 = new FileInputStream("C:\\Presidential\\0x6243E647-sec.asc");
    FileInputStream key2 = new FileInputStream(inputFilename2);
    BufferedInputStream b=new BufferedInputStream(new FileInputStream(inputFilename2));
    KeyBasedFileProcessorUtil.decryptFile(b,key3,a,"aa.txt","C:\\Presidential\\");
  }
}*/

  //---------------------------------method to decrypt our plain text---------------------------------
  public static String extractRsaEncryptedObject(PGPPrivateKey privateKey, String endData)
    throws PGPException, IOException, InterruptedException {
//        byte[] pgpEncryptedData = endData.getBytes(StandardCharsets.UTF_8);
    byte[] pgpEncryptedData = endData.getBytes();
    PGPObjectFactory pgpFact = new BcPGPObjectFactory(pgpEncryptedData);
//        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);
    PGPEncryptedDataList encList;
//        System.out.println("pgpFactory each:");
//        pgpFact.forEach(System.out::println);
//        PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();

    System.out.println("pgpFact.nextObject()");
    Object o = pgpFact.nextObject();
    if (o instanceof PGPEncryptedDataList) {
      encList = (PGPEncryptedDataList) o;
    } else {
      encList = (PGPEncryptedDataList) pgpFact.nextObject();
    }
    // note: we can only do this because we know we match the first encrypted data object
    PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
//        PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);
    PublicKeyDataDecryptorFactory dataDecryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
    InputStream clear = encData.getDataStream(dataDecryptorFactory);
    byte[] literalData = Streams.readAll(clear);
    if (encData.verify()) {
//            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
      PGPObjectFactory litFact = new BcPGPObjectFactory(literalData);
      PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
      byte[] data = Streams.readAll(litData.getInputStream());
//            return new String(data, StandardCharsets.UTF_8);
      return new String(data);
    }
    throw new IllegalStateException("modification check failed");
  }

  //decrypt using private key and
  public static InputStream decryptStream(InputStream in, char[] passwd)
    throws Exception {
    in = PGPUtil.getDecoderStream(in);
    if (in != null) {
      System.out.println("in" + in);
    }
    // general class for reading a stream of data.
    PGPObjectFactory inPgpReader = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
    if (inPgpReader != null) {
      System.out.println("inpgpreadr:" + inPgpReader);
    }
    Object o = inPgpReader.nextObject();
    PGPEncryptedDataList encryptedDataList;
    System.out.println("habibi" + inPgpReader.nextObject() + "again" + o);
    // the first object might be a PGP marker packet.
//    encryptedDataList = (PGPEncryptedDataList) inPgpReader;
    if (o instanceof PGPEncryptedDataList) {
      encryptedDataList = (PGPEncryptedDataList) o;
    } else
    // first object was a marker, the real data is the next one.
    {
      encryptedDataList = (PGPEncryptedDataList) inPgpReader.nextObject();
    }
    // get the iterator so we can iterate through all the encrypted data.
    Iterator encryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
    while (encryptedDataIterator.hasNext()) {
      System.out.println("Printing encrpted data generator:" + encryptedDataIterator.next());
    }//printing encrpted data generator data
    // to be use for decryption
    PGPPrivateKey privateKey = null;
    // a handle to the encrypted data stream
    PGPPublicKeyEncryptedData encryptedDataStreamHandle = null;
    while (privateKey == null && encryptedDataIterator.hasNext()) {
      // a handle to the encrypted data stream
      encryptedDataStreamHandle = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();
      try {
        privateKey =
          findSecretKey(
            pgpSecretKeyRingCollection,
            encryptedDataStreamHandle.getKeyID(),
            passwd);
      } catch (Exception ex) {
        throw new IllegalStateException(
          "decryption exception:  object: "
            + ", Exception when fetching private key using key: "
            + encryptedDataStreamHandle.getKeyID(),
          ex);
      }
    }
    if (privateKey == null) {
      throw new IllegalStateException(
        "decryption exception:  object: "
          + ", Private key for message not found.");
    }
    // finally, lets decrypt the object
    InputStream decryptInputStream = encryptedDataStreamHandle.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
    PGPObjectFactory decryptedDataReader = new PGPObjectFactory(decryptInputStream, new BcKeyFingerprintCalculator());
    Object data = decryptedDataReader.nextObject();
    if (data instanceof PGPLiteralData) {
      PGPLiteralData dataPgpReader = (PGPLiteralData) data;
      // a handle to the decrypted, uncompress data stream
      return dataPgpReader.getInputStream();
    } else if (data instanceof PGPOnePassSignatureList) {
      throw new PGPException(
        "decryption exception:  object: "
          + ", encrypted data contains a signed message - not literal data.");
    } else {
      throw new PGPException(
        "decryption exception:  object: "
          + ", data is not a simple encrypted file - type unknown.");
    }
  }

  public static OutputStream getEncryptedReturnOutputStream(InputStream is, PGPPublicKey pubKey) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(is.readAllBytes());//written to the baos object fetching the data from the input stream.
    // creates a cipher stream which will have an integrity packet associated with it
    PGPEncryptedDataGenerator encryptedDataGenerator =
      new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(PGPEncryptedDataGenerator.CAST5));
    OutputStream out;
    byte[] byteArr;
    try {
      // Add a key encryption method to be used to encrypt the session data associated
      // with this encrypted data
      encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubKey));
      // wrapper around the buffer which will contain the encrypted data.
      out = encryptedDataGenerator.open(bos, new byte[1 << 15]);
//below line jays code
      byteArr = out.toString().getBytes();



      /*


PGPencrypteddatagenerator  returns:  new WrappedGeneratorStream(genOut, this);


         private OutputStream open(
        OutputStream    out,
        long            length,
        byte[]          buffer)


        here we have taken length as 0

        passed

        */

      //convert from outputstream to bytearray (bytestream)

    } catch (Exception e) {
      throw new RuntimeException(
        "Exception when wrapping PGP around our output stream", e);
    }
    /*
     * Open a literal data packet, returning a stream to store the data inside the packet as an indefinite stream.
     * A "literal data packet" in PGP world is the body of a message; data that is not to be further interpreted.
     *
     * The stream is written out as a series of partial packets with a chunk size determine by the size of the passed in buffer.
     * @param outputstream - the stream we want the packet in
     * @param format - the format we are using.
     * @param filename
     * @param the time of last modification we want stored.
     * @param the buffer to use for collecting data to put into chunks.
     */
    try {
      PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
      out =
        literalDataGenerator.open(
          bos,
          PGPLiteralData.BINARY,
          PGPLiteralDataGenerator.CONSOLE,
          new Date(),
          new byte[1 << 15]);

      //below line jays code
    } catch (Exception e) {
      throw new RuntimeException(
        "Exception when creating the PGP encrypted wrapper around the output stream.",
        e);
    }
    return out;
  }

//
//  public static void encrypt() throws Exception {
//    Security.addProvider(new BouncyCastleProvider());
//    //Load Public Key File
//    FileInputStream key = new FileInputStream("C:\\Presidential\\0x6243E647-pub.asc");
//    //PGPPublicKey pubKey2 = KeyBasedFileProcessorUtil.readPublicKey(key3);
//    PGPPublicKey pubKey = KeyBasedFileProcessorUtil.readPublicKey(key);
//    //Output file
//    FileOutputStream out = new FileOutputStream("C:\\Presidential\\enc.bpg");
//    //Input file
//    String inputFilename = "C:\\Presidential\\a.txt";
//    //Other settings
//    boolean armor = false;
//    boolean integrityCheck = false;
//    KeyBasedFileProcessorUtil.encryptFile(out, inputFilename,
//      pubKey, armor, integrityCheck);
//  }




  public static byte[] getEncrypted(String str, PGPPublicKey pubKey) throws IOException {
    InputStream is = IOUtils.toInputStream(str);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(is.readAllBytes());//written to the baos object fetching the data from the input stream.
    // creates a cipher stream which will have an integrity packet associated with it
    PGPEncryptedDataGenerator encryptedDataGenerator =
      new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(PGPEncryptedDataGenerator.CAST5));
    OutputStream out;
    byte[] byteArr;
    try {
      // Add a key encryption method to be used to encrypt the session data associated
      // with this encrypted data
      encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubKey));
      // wrapper around the buffer which will contain the encrypted data.
      out = encryptedDataGenerator.open(bos, new byte[1 << 15]);

      byteArr = out.toString().getBytes();  // might /might not work

    } catch (Exception e) {
      throw new RuntimeException(
        "Exception when wrapping PGP around our output stream", e);
    }
    /*
     * Open a literal data packet, returning a stream to store the data inside the packet as an indefinite stream.
     * A "literal data packet" in PGP world is the body of a message; data that is not to be further interpreted.
     *
     * The stream is written out as a series of partial packets with a chunk size determine by the size of the passed in buffer.
     * @param outputstream - the stream we want the packet in
     * @param format - the format we are using.
     * @param filename
     * @param the time of last modification we want stored.
     * @param the buffer to use for collecting data to put into chunks.
     */
    try {
      PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
      out =
        literalDataGenerator.open(
          bos,
          PGPLiteralData.BINARY,
          PGPLiteralDataGenerator.CONSOLE,
          new Date(),
          new byte[1 << 15]);

    } catch (Exception e) {
      throw new RuntimeException(
        "Exception when creating the PGP encrypted wrapper around the output stream.",
        e);
    }
    ByteArrayOutputStream out1 = new ByteArrayOutputStream();
    out1.writeTo(out);

    return out1.toByteArray();
    //WrappedGeneratorStream
  }

  /*
   * Extract the PGP private key from the encrypted content.  Since the PGP key file contains N number of keys, this method will fetch the
   * private key by "keyID".
   *
   * @param securityCollection - handle to the PGP key file.
   * @param keyID - fetch private key for this value.
   * @param pass - pass phrase used to extract the PGP private key from the encrypted content.
   * @return PGP private key, null if not found.
   */
  private static PGPPrivateKey findSecretKey(
    PGPSecretKeyRingCollection securityCollection, long keyID, char[] pass)
    throws PGPException {
    PGPSecretKey privateKey = securityCollection.getSecretKey(keyID);
    if (privateKey == null) {
      return null;
    }
    return privateKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
      .setProvider(new BouncyCastleProvider()).build(pass));
  }


//  public static void encrypt() throws Exception {
//    Security.addProvider(new BouncyCastleProvider());
//    //Load Public Key File
//    FileInputStream key = new FileInputStream("C:\\Presidential\\0x6243E647-pub.asc");
//    //PGPPublicKey pubKey2 = KeyBasedFileProcessorUtil.readPublicKey(key3);
//    PGPPublicKey pubKey = KeyBasedFileProcessorUtil.readPublicKey(key);
//    //Output file
//    FileOutputStream out = new FileOutputStream("C:\\Presidential\\enc.bpg");
//    //Input file
//    String inputFilename = "C:\\Presidential\\a.txt";
//    //Other settings
//    boolean armor = false;
//    boolean integrityCheck = false;
//    KeyBasedFileProcessorUtil.encryptFile(out, inputFilename,
//      pubKey, armor, integrityCheck);
//  }




  public static byte[] decryptPGP(byte[] message, PrivateKey key) throws GeneralSecurityException, PGPException, IOException {
    ByteBuffer buffer = ByteBuffer.wrap(message);
    int keyLength = buffer.getInt();
    byte[] encyptedPublicKey = new byte[keyLength];
    buffer.get(encyptedPublicKey);

    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, key);

    byte[] encodedPublicKey = cipher.doFinal(encyptedPublicKey);
    String s = new String(encodedPublicKey);
    PublicKey publicKey = (PublicKey) getPublicKey(s);
    cipher.init(Cipher.DECRYPT_MODE, publicKey);

    byte[] encryptedMessage = new byte[buffer.remaining()];
    buffer.get(encryptedMessage);

    return cipher.doFinal(encryptedMessage);
  }


  public static String encryptMessagePgp(String plainText, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
  }
  public static String decryptMessagePgp(String encryptedText, PrivateKey privateKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
  }

  // ---------------------------------main method---------------------------------
  public static void main(String[] args) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    String stringToEncryptAndDecrypt = "this is the string to be encrypted and decrypted";
    byte[] original = stringToEncryptAndDecrypt.getBytes();
    String passphrase = "jayrathod";
    System.out.println(encryptMessagePgp("plain text", getPublicKey("C:\\Users\\jay\\Desktop\\gpgalgorithm\\publickey.asc")));

    System.out.println("pvtkey: " + getPrivateKey(pvtKey));
    System.out.println( decryptMessagePgp(encryptMessagePgp("plain text", getPublicKey("C:\\Users\\jay\\Desktop\\gpgalgorithm\\publickey.asc")),getPrivateKey(pvtKey) ));
//    PGPPublicKey pgpPublicKey = getPublicKey("C:\\Users\\jay\\Desktop\\gpgalgorithm\\publickey.asc");
//    System.out.println("pubkey:" + pgpPublicKey);
//    System.out.println("Jay string encrypted" + getEncrypted("Jay", pgpPublicKey));
    //    InputStream targetStream = new ByteArrayInputStream(   getEncrypted("Jay", pgpPublicKey));

//    System.out.println("-------------------this is the byte array---------------" + Arrays.toString());
//    System.out.println(decryptStream(targetStream, "jayrathod".toCharArray()));
//    String str=new String(=);

//    System.out.println(getPlainTextFromEncrpytedMessage(getEncrypted("Jay", pgpPublicKey),"jayrathod"));
//    System.out.println(extractRsaEncryptedObject(getPrivateKey(pvtKey), new String( getEncrypted("Jay", pgpPublicKey))));

// System.out.println(getPlainTextFromEncrpytedMessage(getEncrypted(new ByteArrayInputStream("JAY".getBytes()), pgpPublicKey), "jayrathod"));
//    System.out.println(     Base64.getEncoder().encodeToString( decryptPGP(getEncrypted("Jay", pgpPublicKey), getPrivateKey(pvtKey))));

//    System.out.println(   "decrpypted message:" +  decryptMessagePgp( new String(getEncrypted("Jay", pgpPublicKey)), getPrivateKey(pvtKey)));

//    Base64.getEncoder().encodeToString( decryptPGP(getEncrypted("Jay", pgpPublicKey), getPrivateKey(pvtKey)))
    //THE TESTING PHASE

    //END OF THE TESTING PHASE

//    System.out.println(pgpPublicKey);
//    System.out.println(getEncryptedMessage(stringToEncryptAndDecrypt, pgpPublicKey));
//
//    ;
//    byte[] stringToEncryptAndDecryptBytes = stringToEncryptAndDecrypt.getBytes();
//    SpringApplication.run(GpgalgorithmApplication.class, args);//run method
//
//    System.out.println("Cipher text:" + encryptedString);
////    byte[] plainText = getPlainTextFromEncrpytedMessage(encryptedString, passphrase);
////    String s = new String(plainText);
////    System.out.println(s);
//
//    InputStream in = new ByteArrayInputStream(encryptedString.getBytes());
//
//
//    //findSecretKey("C:\\Users\\jay\\Desktop\\gpgalgorithm\\secretkey.asc", , "jayrathod");
//    extractRsaEncryptedObject(getPrivateKey(pvtKey), encryptedString);
//    decryptStream(in, passphrase.toCharArray(), "Object_name_jay");
//    System.out.println("Cipher text to plain text" + string);

//    PublicKeyAlgorithmTags.RSA_ENCRYPT

  }

}
