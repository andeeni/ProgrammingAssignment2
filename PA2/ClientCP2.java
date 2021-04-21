import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;


public class ClientCP2 {
    public static void main(String[] args) throws Exception {

		//create X509CertificateObject
		InputStream fis = new FileInputStream("C:\\Users\\Deeni\\OneDrive - Singapore University of Technology and Design\\Desktop\\50.005 CSE\\ProgrammingAssignment2\\PA2\\cacsertificate.crt");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		//get CA cert
		X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);

		//get CA public key
		PublicKey CAPublicKey = CAcert.getPublicKey();

    	String serverAddress = "localhost";
    	int port = 4321;

		int numBytes = 0;

		Socket clientSocket = null;
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());
			
			//AP
			toServer.writeInt(10);
			//generate nonce
            byte[] nonce = new byte[32];
			SecureRandom randomGenerator = new 
			SecureRandom();
			randomGenerator.nextBytes(nonce);

            //send nonce to server
            toServer.writeInt(nonce.length);
			toServer.write(nonce);
			//TODO: flush?
            //toServer.flush();

            //read encrypted nonce from server
			int encryptedNonceLength = fromServer.readInt();
            byte[] encryptedNonce = new byte[encryptedNonceLength];
            fromServer.readFully(encryptedNonce);
			
			//retrieve server cert signed by CA
			toServer.writeInt(11); 
			String serverCertString = fromServer.readUTF();

			byte[] certBytes = Base64.getDecoder().decode(serverCertString);
        	InputStream inputStream = new ByteArrayInputStream(certBytes);

			CertificateFactory cfac = CertificateFactory.getInstance("X.509");
			X509Certificate serverCert = (X509Certificate) cfac.generateCertificate(inputStream);

			//retrieve server public key from cert
			PublicKey serverPublicKey = serverCert.getPublicKey();

            // verify server's cert
			try {
				serverCert.checkValidity();
				serverCert.verify(CAPublicKey);
			} catch (Exception e) {
				//invalid cert, close connection
				e.printStackTrace();
				toServer.writeInt(12); 
				System.out.println("Closing connection...");
				clientSocket.close();
			}

            // verify that server owns private key associated with public key in the cert
			// decrypt encryptedMessage sent by server with server's public key
			Cipher dCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);

            byte[] decryptedNonce = dCipher.doFinal(encryptedNonce);

			//check if decrypted msg = original msg
            if (Arrays.equals(decryptedNonce, nonce)) {
                System.out.println("Nonce verified"); //handshake
            }else{
                System.out.println("Nonce verification failed");
				toServer.close();
				fromServer.close();
				clientSocket.close();
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // point 1: Generate AES symmetric key
            keyGen.init(128);
            Key AESkey = keyGen.generateKey();

            // send sym key to server
			toServer.writeInt(13);
			
            Cipher eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            eCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			//point 2: Send symmetric key to server (encrypted with server’s public key)
            byte[] encBytesArray = eCipher.doFinal(AESkey.getEncoded());

			toServer.writeUTF(Base64.getEncoder().encodeToString(encBytesArray)
            );
            //

			for (int i = 0; i < args.length; i++) {
				String filename = args[i];

				//handshake
				System.out.println("Sending " + filename + "...");
				// Send the filename
				toServer.writeInt(0);
				toServer.writeInt(filename.getBytes().length);
				toServer.write(filename.getBytes());
				toServer.flush();

				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				byte [] fromFileBuffer = new byte[117];

				// Send the file
				for (boolean fileEnded = false; !fileEnded;) {

					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					fileEnded = numBytes < 117;

					toServer.writeInt(1);
					toServer.writeInt(numBytes);

                    Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    aesCipher.init(Cipher.ENCRYPT_MODE, AESkey);
                    // point 3: Encrypt file chunk with AES symmetric key
                    byte [] cipherTextLong = aesCipher.doFinal(fromFileBuffer);

					int numBytesEncryted = cipherTextLong.length;
					toServer.writeInt(numBytesEncryted);
				
					//send data
					toServer.write(cipherTextLong);
					toServer.flush();
				}

				System.out.println(filename + " sent");

				if (i == args.length - 1) {
					// end of file transfer
					toServer.writeInt(3);
					bufferedFileInputStream.close();
					fileInputStream.close();
				}
			}

			System.out.println("Closing connection...");

		} catch (Exception e) {
			e.printStackTrace();
		}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
