package hybrid.decrypt;

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

public class StartDecryption {
	
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
	
	public void StartDecryptionProcess() throws IOException, GeneralSecurityException, Exception{
		StartDecryption startEnc = new StartDecryption();

		File encryptedKeyReceived = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedSecretKey");
		File decreptedKeyFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\DecryptedFiles\\SecretKey");
		new DecryptKey(startEnc.getPrivate("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\KeyPair\\privateKey_Bob", "RSA"), encryptedKeyReceived, decreptedKeyFile, "RSA");

		//This code is to decrypt txt file
		File encryptedFileReceived = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedFile.txt");
		File decryptedFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\DecryptedFiles\\decryptedFile.txt");

        //This code is to decrypt Microsoft Word file
//      File encryptedFileReceived = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedFile.docx");
//		File decryptedFile = new File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\DecryptedFiles\\decryptedFile.docx");
		new DecryptData(encryptedFileReceived, decryptedFile, startEnc.getSecretKey("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\DecryptedFiles\\SecretKey", "AES"), "AES");
	}
}
