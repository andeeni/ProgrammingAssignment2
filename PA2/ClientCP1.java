import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

public class ClientCP1 {
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
            toServer.writeInt(10); //ask to prove identity
            //generate nonce
            byte[] nonce = new byte[32];
			SecureRandom randomGenerator = new SecureRandom();
			randomGenerator.nextBytes(nonce);

            //send nonce to server
            toServer.writeInt(nonce.length);
			toServer.write(nonce);
			//TODO: flush?
            // toServer.flush();

            //read encrypted nonce from server
			int encryptedNonceLength = fromServer.readInt();
            byte[] encryptedNonce = new byte[encryptedNonceLength];
            fromServer.readFully(encryptedNonce);
            
            //ask for cert signed by CA
            toServer.writeInt(11); 

            //point 1: Get server.crt from server
            String serverCertString = fromServer.readUTF();

            byte[] certBytes = Base64.getDecoder().decode(serverCertString);
            InputStream inputStream = new ByteArrayInputStream(certBytes);

            CertificateFactory cfac = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) cfac.generateCertificate(inputStream);

            //point 3: Extract server's public key from the certificate
            PublicKey serverPublicKey = serverCert.getPublicKey(); 

            //point 2: Verify (and decrypt) the server.crt using CA cert
            try {
                serverCert.checkValidity();
                serverCert.verify(CAPublicKey); 
            } catch (Exception e) {
                e.printStackTrace();
                toServer.writeInt(71); //invalid cert, close connection
                System.out.println("Closing connection...");
                clientSocket.close();
            }

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

            for (int i = 0; i < args.length; i++) {
                String filename = args[i];

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

                    Cipher cipherServer = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherServer.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                    // point 4: Encrypt file chunks with server’s public key
                    byte[] cipherTextLong = cipherServer.doFinal(fromFileBuffer);

                    int numBytesEncryted =  cipherTextLong.length;
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
