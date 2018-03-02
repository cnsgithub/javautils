import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.util.Arrays;

/**
 This class should be used for new encryption appliances, as it will automatically use a modern approach.

 Useful read:
 https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
 https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
 The "standard" encryption method is 256-bit AES using PKCS #5's PBKDF2 (Password-Based Key Derivation Function #2).
 This method requires Java 6. The password used to generate the SecretKey should be kept in a secure place and not be shared.
 The salt is used to prevent dictionary attacks against the key in the event your encrypted data is compromised.
 A 16-byte random initialization vector is also applied so each encrypted message is unique.
 Also compared to plain JAVA this does not need the JCE http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
 ----------------------------------
 This util uses CipherAlgorithm.GCM
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class SpringAESCrypto {

    private String password;
    private String salt;

    public SpringAESCrypto(String password){
        this.password = password;
        this.salt = KeyGenerators.string().generateKey();
    }

    public String encrypt(String plain){
        TextEncryptor textEncryptor = Encryptors.delux(password, salt);
        return textEncryptor.encrypt(plain);
    }

    public String decrypt(String ciphered){
        TextEncryptor textEncryptor = Encryptors.delux(password, salt);
        return textEncryptor.decrypt(ciphered);
    }

    public byte[] encrypt(byte[] bytes){
        BytesEncryptor bytesEncryptor = Encryptors.stronger(password, salt);
        return bytesEncryptor.encrypt(bytes);
    }

    public byte[] decrypt(byte[] ciphered){
        BytesEncryptor bytesEncryptor = Encryptors.stronger(password, salt);
        return bytesEncryptor.decrypt(ciphered);
    }

    public static void main(String[] args) {
        //Usage example of util class
        String plain = "*royal secrets*";
        SpringAESCrypto c = new SpringAESCrypto("I AM SHERLOCKED");
        String ciphered = c.encrypt(plain);
        System.out.println(ciphered);
        System.out.println("Bytes used: " +ciphered.getBytes().length);
        System.out.println(c.decrypt(ciphered));

        //Prefer bytes encryption if you want to save memory or want to keep the payload small
        byte[] b = new byte[]{-128, -64, 0, 64, 127};
        System.out.println(Arrays.toString(b));
        byte[] b_c = c.encrypt(b);
        System.out.println(Arrays.toString(b_c));
        System.out.println("Bytes used: " + b_c.length);
        System.out.println(Arrays.toString(c.decrypt(b_c)));
    }

}
