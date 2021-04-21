import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.Cipher;

public class ServerCP1 {

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

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // AP
                //authenticate identity of the server, dont leak data
                if (packetType == 10) {
                    //receive nonce from client
                    int nonceLength = fromClient.readInt();
                    byte[] nonce = new byte[nonceLength];
                    // Read nonce from client
                    fromClient.readFully(nonce);

                    Cipher eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    eCipher.init(Cipher.ENCRYPT_MODE, serverPrivateKey);

                    // point 2: Encrypt nonce with private key
                    byte[] encryptedNonce = eCipher.doFinal(nonce);

                    //send encrypted nonce to client
                    toClient.writeInt(encryptedNonce.length);
                    toClient.write(encryptedNonce);
                    //TODO: flush?
                    // toClient.flush();
                }
                // point 1: send (signed) server cert to client
                if (packetType == 11) {
                    toClient.writeUTF(Base64.getEncoder().encodeToString(serverCert.getEncoded())); //write servercert string
                }

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recvCP1_"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    int numBytes = fromClient.readInt(); // no. bytes before encryption, to be written
                    int numBytesEncrypted = fromClient.readInt(); // no. bytes after encryption, to be read from buffer
                    byte [] block = new byte[numBytesEncrypted]; 
                    fromClient.readFully(block, 0, numBytesEncrypted);

                    Cipher rsaCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, serverPrivateKey);
                    
                    // point 3: Decrypt file chunks with server private key
                    byte[] blockDecrypted = rsaCipherDecrypt.doFinal(block); 

                    if (numBytes > 0)
                        bufferedFileOutputStream.write(blockDecrypted, 0, numBytes);

                    if (numBytes < 117) {
                        System.out.println("Received file");

                        if (bufferedFileOutputStream != null)       bufferedFileOutputStream.close();
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

