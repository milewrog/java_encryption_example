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
  public static final String KEY_ALGORITHM    = "AES";
  public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  public static final int    KEY_LENGTH_BITS  = 256;
  public static final int    IV_LENGTH_BYTES  = 16;                           // 256/8 = 32; however, iv must be 16 bytes long (TODO: why?).

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
    KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
    SecureRandom random = new SecureRandom();
    generator.init(KEY_LENGTH_BITS, random);
    return generator.generateKey();
  }

  private static IvParameterSpec generateInitializationVector()
  {
    SecureRandom random = new SecureRandom();
    return new IvParameterSpec(random.generateSeed(IV_LENGTH_BYTES));
  }

  private static Cipher newCipher(SecretKey symmetricKey, IvParameterSpec iv) throws Exception
  {
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, iv);
    return cipher;
  }
}


//
// Decrypts byte arrays using a symmetric key.
//
class SymmetricDecryptor
{
  public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

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
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, symmetricKey, iv);
    return cipher;
  }
}


//
// Encrypts byte arrays using an asymmetric key pair.
//
class AsymmetricEncryptor
{
  public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

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
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher;    
  }
}


//
// Decrypts byte arrays using an asymmetric key pair.
//
class AsymmetricDecryptor
{
  public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

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
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return cipher;    
  }
}


//
// Reads public and private keys from a file.
//
class AsymmetricKeyReader
{
  public static final String KEY_ALGORITHM = "RSA";

  public static PrivateKey readPrivateKey(String filenameDer) throws Exception
  {
    byte[] keyBytes = readAllBytes(filenameDer);
    KeyFactory keyFactory = newKeyFactory();
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    return keyFactory.generatePrivate(spec);
  }

  public static PublicKey readPublicKey(String filenameDer) throws Exception
  {
    byte[] keyBytes = readAllBytes(filenameDer);
    KeyFactory keyFactory = newKeyFactory();
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    return keyFactory.generatePublic(spec);
  }

  private static byte[] readAllBytes(String filename) throws Exception
  {
    return Files.readAllBytes(Paths.get(filename));
  }

  private static KeyFactory newKeyFactory() throws Exception
  {
    return KeyFactory.getInstance(KEY_ALGORITHM);
  }
}


class Main
{
  public static final String PUBLIC_KEY_FILENAME  = "public_key.der";
  public static final String PRIVATE_KEY_FILENAME = "private_key.der";
  public static final String SECRET_KEY_ALGORITHM = "AES";

  public static void main(String[] args)
  {
    try
    {
      // A message to be sent encrypted.
      String message = "this is a message";
      System.out.printf("input message:  %s\n", message);
      byte[] messageBytes = message.getBytes();

      // Encrypt the message with a new symmetric key.
      SymmetricEncryptor symmetricEncryptor = new SymmetricEncryptor();
      byte[] encryptedMessage = symmetricEncryptor.encrypt(messageBytes);

      // Read public key from file, for encrypting symmetric key.
      PublicKey publicKey = AsymmetricKeyReader.readPublicKey(PUBLIC_KEY_FILENAME);

      // Encrypt the symmetric key with the public key.
      AsymmetricEncryptor asymmetricEncriptor = new AsymmetricEncryptor(publicKey);
      byte[] secretKeyBytes = symmetricEncryptor.getKey().getEncoded();
      byte[] encryptedSecretKey = asymmetricEncriptor.encrypt(secretKeyBytes);

      // Encrypt the symmetric key initialization vector with the public key.
      byte[] ivBytes = symmetricEncryptor.getInitializationVector().getIV();
      byte[] encryptedIV = asymmetricEncriptor.encrypt(ivBytes);

      // <encryptedMessage, encryptedSecretKey, and encryptedIV ARE SENT AND RECEIVED HERE>

      // Read private key from file.
      PrivateKey privateKey = AsymmetricKeyReader.readPrivateKey(PRIVATE_KEY_FILENAME);

      // Decrypt the symmetric key with the private key.
      AsymmetricDecryptor asymmetricDecryptor = new AsymmetricDecryptor(privateKey);
      byte[] receivedSecretKeyBytes = asymmetricDecryptor.decrypt(encryptedSecretKey);
      SecretKey receivedSecretKey = new SecretKeySpec(receivedSecretKeyBytes, SECRET_KEY_ALGORITHM);

      // Decrypt the symmetric key initialization vector with the private key.
      byte[] receivedIVBytes = asymmetricDecryptor.decrypt(encryptedIV);
      IvParameterSpec receivedIV = new IvParameterSpec(receivedIVBytes);

      // Decrypt the message.
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
