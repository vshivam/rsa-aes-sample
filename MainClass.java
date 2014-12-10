import java.io.BufferedReader;
import java.io.FileReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.spongycastle.util.encoders.Base64;

public class MainClass {

	private static final String TRANSFORMATION = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
	private static final String SECURITY_PROVIDER = "SC";

	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
		String encryptedString = "kYBqx4+YSpT2eTLQKs9t2QsemCg//BXK7RZuOYdFOMd+dpXcUA/oKXXW2JGhFulswWLhsLRdPFy0HxZ0kzUv0SpLdNco6FtlX51pS0uhTGVgen8up4qSXjToHhcoz2A31IYI4t89MkL/FKeYZgL5600idF1pIIdae0Sg8nf0xsRHdW3qk/RcmYwHyxB+p/ln4EglkcrC89bGEXKqqylUqHiTZJWkohKsLbd5hPVENZidO61ha1mu5irZOYNlJzK/d7cPpiBul9iMx5/ZUxIDc/TBlhMzGNG++19jqITVp1FmPr7zI1m+LAmcZbx6JC4hFZ0S9qi81J5ZiPBi5p4Yog==";
		byte[] decryptedStringStream = decryptSecretKeyData(Base64
				.decode(encryptedString.getBytes()));
		System.out.println(new String(decryptedStringStream, 0,
				decryptedStringStream.length));
	}

	static byte[] decryptSecretKeyData(byte[] encryptedSecretKey) {
		Cipher rsaCipher;
		try {
			PrivateKey privateKey = getPrivateKey();
			rsaCipher = Cipher.getInstance(TRANSFORMATION, SECURITY_PROVIDER);
			rsaCipher
					.init(Cipher.DECRYPT_MODE, privateKey,
							new OAEPParameterSpec("SHA-256", "MGF1",
									MGF1ParameterSpec.SHA1,
									PSource.PSpecified.DEFAULT));
			return rsaCipher.doFinal(encryptedSecretKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static PrivateKey getPrivateKey() throws Exception {
		String everything;
		BufferedReader br = new BufferedReader(new FileReader(
				"/home/shivam/work/workspace/TestProject/src/private_key.pem"));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			everything = sb.toString();
		} finally {
			br.close();
		}
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
				Base64.decode(everything.getBytes()));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(keySpec);
	}
}