package hybrid.encrypt;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.SecretKeySpec;

public class StartEncryption {
	
	public PrivateKey getPrivate(String filename, String algorithm) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(spec);
	}

	public PublicKey getPublic(String filename, String algorithm) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePublic(spec);
	}
	
	public SecretKeySpec getSecretKey(String filename, String algorithm) throws IOException{
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		return new SecretKeySpec(keyBytes, algorithm);
	}
	
	public void StartEncryptionProcess() throws IOException, GeneralSecurityException, Exception{
		StartEncryption startEnc = new StartEncryption();

		File originalKeyFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\OneKey\\secretKey");
		File encryptedKeyFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedSecretKey");
		new EncryptKey(startEnc.getPublic("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\KeyPair\\publicKey_Bob", "RSA"), originalKeyFile, encryptedKeyFile, "RSA");

		//This code is to encrypt txt file
		File originalFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\OriginalFile\\confidential.txt");
		File encryptedFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedFile.txt");

        //This code is to encrypt Microsoft Word Files
//      File originalFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\OriginalFile\\HelloWorld.docx");
//		File encryptedFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedFile.docx");
		new EncryptData(originalFile, encryptedFile, startEnc.getSecretKey("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\OneKey\\secretKey", "AES"), "AES");
	}
}
