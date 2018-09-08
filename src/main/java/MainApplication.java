import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.google.api.client.http.FileContent;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;

import hybrid.decrypt.StartDecryption;
import hybrid.encrypt.StartEncryption;

public class MainApplication {

    private static final String APPLICATION_NAME = "Secure Cloud Storage Using Hybrid Cryptography";
    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    private static final String CREDENTIALS_FOLDER = "credentials"; // Directory to store user credentials.
    private static Drive service;
    private static BufferedReader br;

    /**
     * Global instance of the scopes required by this quickstart.
     * If modifying these scopes, delete your previously saved credentials/ folder.
     */
    private static final List<String> SCOPES = Collections.singletonList(DriveScopes.DRIVE);
    private static final String CLIENT_SECRET_DIR = "client_secret.json";

    /**
     * Creates an authorized Credential object.
     * @param HTTP_TRANSPORT The network HTTP Transport.
     * @return An authorized Credential object.
     * @throws IOException If there is no client_secret.
     */
    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
        // Load client secrets.
        InputStream in = MainApplication.class.getResourceAsStream(CLIENT_SECRET_DIR);
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(CREDENTIALS_FOLDER)))
                .setAccessType("offline")
                .build();
        return new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize("user");
    }

    public void EncryptAndUpload() throws Exception {
        StartEncryption encryption = new StartEncryption();
        encryption.StartEncryptionProcess();

        //Upload The Encrypted txt File
        File fileMetadata = new File();
        fileMetadata.setName("EncryptedFile.txt");
        java.io.File filePath = new java.io.File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedFile.txt");
        FileContent mediaContent = new FileContent("text/plain", filePath);
        File file = service.files().create(fileMetadata, mediaContent)
                .setFields("id")
                .execute();
        System.out.println("File Uploaded Successfully. File ID: " + file.getId());
        filePath.delete();
    }

    public void ViewDriveFiles() throws IOException {
        FileList result = service.files().list()
                .setQ("mimeType = 'text/plain'")
                .setFields("nextPageToken, files(id, name)")
                .execute();
        List<File> files = result.getFiles();
        if (files == null || files.isEmpty()) {
            System.out.println("No files found.");
        } else {
            System.out.println("Files:");
            for (File file : files) {
                System.out.printf("%s (%s)\n", file.getName(), file.getId());
            }
        }
    }

    public void DownloadAndDecrypt() throws Exception {
        br = new BufferedReader(new InputStreamReader(System.in));
        String decryptedFile = "C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\DecryptedFiles\\decryptedFile.txt";
        System.out.println("Please Enter The File ID to Download From Google Drive");
        String fileId = br.readLine();
        OutputStream outputStream = new ByteArrayOutputStream();
        service.files().get(fileId)
                .executeMediaAndDownloadTo(outputStream);
        System.out.println(outputStream);

        FileOutputStream fop = null;
        java.io.File file;

        try {
            file = new java.io.File("C:\\Users\\Bitan Basak\\Desktop\\secure-cloud\\src\\main\\resources\\EncryptedFiles\\encryptedFile.txt");
            fop = new FileOutputStream(file);

            // if file doesnt exists, then create it
            if (!file.exists()) {
                file.createNewFile();
            }

            fop.write(((ByteArrayOutputStream) outputStream).toByteArray());
            fop.flush();
            fop.close();

            System.out.println("Done Downloading File!");

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fop != null) {
                    fop.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Starting Decryption Process!");
        StartDecryption decryption = new StartDecryption();
        decryption.StartDecryptionProcess();
        System.out.println("Decryption Complete! Decrypted File Location: "+decryptedFile);
    }

    public static void main(String args[]) throws GeneralSecurityException, IOException {
        int ch = 1;

        br = new BufferedReader(new InputStreamReader(System.in));

        // Build a new authorized API client service.
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        service = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
                .setApplicationName(APPLICATION_NAME)
                .build();

        MainApplication main = new MainApplication();

        while(ch != 4) {
            System.out.println();
            System.out.println("Secure Cloud Storage Using Hybrid Cryptography:");
            System.out.println("1. Encrypt and Upload");
            System.out.println("2. View Drive Files");
            System.out.println("3. Download and Decrypt");
            System.out.println("4. Exit");
            System.out.print("Please Enter Your Choice: ");
            ch = Integer.parseInt(br.readLine());

            switch (ch) {
                case 1:
                    try {
                        main.EncryptAndUpload();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    break;
                case 2:
                    try {
                        main.ViewDriveFiles();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    break;
                case 3:
                    try {
                        main.DownloadAndDecrypt();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    break;
                case 4: System.exit(1);
                default:
                    System.out.println("Wrong User Input");
            }
        }
    }
}
