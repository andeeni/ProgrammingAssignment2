import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ServerCP2 {

    public static void main(String[] args) throws Exception{

        InputStream fis = new FileInputStream("C:\\Users\\Deeni\\OneDrive - Singapore University of Technology and Design\\Desktop\\50.005 CSE\\ProgrammingAssignment2\\PA2\\certificate_1004481.crt");
        
        //get server cert
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert = (X509Certificate) cf.generateCertificate(fis);

        //get server private key
        PrivateKey serverPrivateKey;
        serverPrivateKey = PrivateKeyReader.get("C:\\Users\\Deeni\\OneDrive - Singapore University of Technology and Design\\Desktop\\50.005 CSE\\ProgrammingAssignment2\\PA2\\private_key.der");

        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            //initialise key
            Key AESKey = new SecretKeySpec("test".getBytes(), 0, 1, "AES"); //key, offset, len, algo

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // AP
                if (packetType == 10) {
                    //receive nonce from client
                    int nonceLength = fromClient.readInt();
                    byte[] nonce = new byte[nonceLength];
                    // Read nonce from client
                    fromClient.readFully(nonce);

					Cipher eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                	eCipher.init(Cipher.ENCRYPT_MODE, serverPrivateKey);

                	//encrypt nonce
                    byte[] encryptedNonce = eCipher.doFinal(nonce);

                    //send encrypted nonce to client
                    toClient.writeInt(encryptedNonce.length);
                    toClient.write(encryptedNonce);
                    //TODO: flush?
                    // toClient.flush();
                }

                if (packetType == 11) {
                    toClient.writeUTF(Base64.getEncoder().encodeToString(serverCert.getEncoded())); //write server sert string
                }

                if (packetType == 12) {
                    System.out.println("Certificate verification failed, closing connection");
                }

                // read msg from socket
                if (packetType == 13) {
                    //get sym key
					String symKey = fromClient.readUTF();

                    Cipher rsaCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, serverPrivateKey);

                    byte[] aesKeybytesDecryptedKey = rsaCipherDecrypt.doFinal(Base64.getDecoder().decode(symKey)); // point 1: Decrypt symmetric key with server private key

					AESKey = new SecretKeySpec(aesKeybytesDecryptedKey, 0, aesKeybytesDecryptedKey.length, "AES");

				}

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recvCP2_"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    int numBytes = fromClient.readInt(); // no. bytes before encryption
                    int numBytesEncrypted = fromClient.readInt();
                    byte [] block = new byte[numBytesEncrypted]; 
                    fromClient.readFully(block, 0, numBytesEncrypted);

                    Cipher aesCipherDecryptor = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    aesCipherDecryptor.init(Cipher.DECRYPT_MODE, AESKey);
                    //decrypt
                    byte [] decryptedblock = aesCipherDecryptor.doFinal(block); // point 2: Decrypt file chunks with symmetric key

                    if (numBytes > 0)
                        bufferedFileOutputStream.write(decryptedblock, 0, numBytes);

                    if (numBytes < 117) {
                        System.out.println("Received file");

                        if (bufferedFileOutputStream != null) 		bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                    }
                }
                
                //End of transfer
                if (packetType == 3) { 
                    System.out.println("Closing connection...");
                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}

