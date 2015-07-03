import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;


//
// Encrypts byte arrays using a symmetric key.
//
class SymmetricEncryptor
{
  private SecretKey _key;
  private IvParameterSpec _iv;
  private Cipher _cipher;

  public SymmetricEncryptor() throws Exception
  {
    _key = generateSymmetricKey();
    _iv = generateInitializationVector();
    _cipher = newCipher(_key, _iv);
  }
  
  public byte[] encrypt(byte[] clearMessage) throws Exception
  {
    return _cipher.doFinal(clearMessage);
  }

  public SecretKey getKey()
  {
    return _key;
  }

  public IvParameterSpec getInitializationVector()
  {
    return _iv;
  }

  private static SecretKey generateSymmetricKey() throws Exception
  {
    KeyGenerator generator = KeyGenerator.getInstance("AES");                 // TODO: extract constant
    SecureRandom random = new SecureRandom();
    generator.init(256, random);                                              // TODO: extract constant
    return generator.generateKey();
  }

  private static IvParameterSpec generateInitializationVector()
  {
    SecureRandom random = new SecureRandom();
    return new IvParameterSpec(random.generateSeed(16));                      // TODO: extract constant
  }

  private static Cipher newCipher(SecretKey symmetricKey, IvParameterSpec iv) throws Exception
  {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");               // TODO: extract constant
    cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, iv);
    return cipher;
  }
}


//
// Decrypts byte arrays using a symmetric key.
//
class SymmetricDecryptor
{
  private Cipher _cipher;

  public SymmetricDecryptor(SecretKey key, IvParameterSpec iv) throws Exception
  {
    _cipher = newCipher(key, iv);
  }

  public byte[] decrypt(byte[] encryptedMessage) throws Exception
  {
    return _cipher.doFinal(encryptedMessage);
  }

  private static Cipher newCipher(SecretKey symmetricKey, IvParameterSpec iv) throws Exception
  {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");               // TODO: extract constant
    cipher.init(Cipher.DECRYPT_MODE, symmetricKey, iv);
    return cipher;
  }
}


//
// Encrypts byte arrays using an asymmetric key pair.
//
class AsymmetricEncryptor
{
  private Cipher _cipher;

  public AsymmetricEncryptor(PublicKey publicKey) throws Exception
  {
    _cipher = newCipher(publicKey);
  }

  public byte[] encrypt(byte[] clearMessage) throws Exception
  {
    return _cipher.doFinal(clearMessage);
  }

  private static Cipher newCipher(PublicKey publicKey) throws Exception
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");               // TODO: extract constant
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher;    
  }
}


//
// Decrypts byte arrays using an asymmetric key pair.
//
class AsymmetricDecryptor
{
  private Cipher _cipher;

  public AsymmetricDecryptor(PrivateKey privateKey) throws Exception
  {
    _cipher = newCipher(privateKey);
  }

  public byte[] decrypt(byte[] encryptedMessage) throws Exception
  {
    return _cipher.doFinal(encryptedMessage);
  }

  public static Cipher newCipher(PrivateKey privateKey) throws Exception
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");               // TODO: extract constant
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return cipher;    
  }
}


//
// Reads public and private keys from a file.
//
class AsymmetricKeyReader
{
  public static PrivateKey readPrivateKey(String filenameDer) throws Exception
  {
    byte[] keyBytes = Files.readAllBytes(Paths.get(filenameDer));
    KeyFactory keyFactory = newKeyFactory();
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    return keyFactory.generatePrivate(spec);
  }

  public static PublicKey readPublicKey(String filenameDer) throws Exception
  {
    byte[] keyBytes = Files.readAllBytes(Paths.get(filenameDer));
    KeyFactory keyFactory = newKeyFactory();
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    return keyFactory.generatePublic(spec);
  }

  private static KeyFactory newKeyFactory() throws Exception
  {
    return KeyFactory.getInstance("RSA");
  }
}


class Main
{
  public static void main(String[] args)
  {
    try
    {
      // A message to be sent encrypted.
      String message = "this is a message";
      System.out.printf("input message:  %s\n", message);
      byte[] messageBytes = message.getBytes();

      // Encrypt the message with a symmetric key.
      SymmetricEncryptor symmetricEncryptor = new SymmetricEncryptor();
      byte[] encryptedMessage = symmetricEncryptor.encrypt(messageBytes);

      // Read public key from file.
      PublicKey publicKey = AsymmetricKeyReader.readPublicKey("public_key.der");          // TODO: extract constant

      // Encrypt the symmetric key with an asymmetric key.
      AsymmetricEncryptor asymmetricEncriptor = new AsymmetricEncryptor(publicKey);
      byte[] secretKeyBytes = symmetricEncryptor.getKey().getEncoded();
      byte[] encryptedSecretKey = asymmetricEncriptor.encrypt(secretKeyBytes);

      // Encrypt the symmetric key initialization vector with an asymmetric key.
      byte[] symmetricInitializationVectorBytes = symmetricEncryptor.getInitializationVector().getIV();
      byte[] encryptedIV = asymmetricEncriptor.encrypt(symmetricInitializationVectorBytes);

      // <encryptedMessage, encryptedSecretKey, and encryptedIV ARE SENT HERE>

      // Read private key from file.
      PrivateKey privateKey = AsymmetricKeyReader.readPrivateKey("private_key.der");      // TODO: extract constant

      // Decrypt the symmetric key with the asymmetric key.
      AsymmetricDecryptor asymmetricDecryptor = new AsymmetricDecryptor(privateKey);
      byte[] receivedSecretKeyBytes = asymmetricDecryptor.decrypt(encryptedSecretKey);
      SecretKey receivedSecretKey = new SecretKeySpec(receivedSecretKeyBytes, "AES");     // TODO: extract constant

      // Decrypt the symmetric key initialization vector with the asymmetric key.
      byte[] receivedIVBytes = asymmetricDecryptor.decrypt(encryptedIV);
      IvParameterSpec receivedIV = new IvParameterSpec(receivedIVBytes);

      // Descrypt the message.
      SymmetricDecryptor symmetricDecryptor = new SymmetricDecryptor(receivedSecretKey, receivedIV);
      byte[] receivedMessageBytes = symmetricDecryptor.decrypt(encryptedMessage);

      // The message that was received.
      String receivedMessage = new String(receivedMessageBytes, "UTF8");
      System.out.printf("output message: %s\n", receivedMessage);
    }
    catch (Exception ex)
    {
      ex.printStackTrace();
    }
  }
}
