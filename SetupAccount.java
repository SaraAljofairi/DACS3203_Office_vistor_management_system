package ovms;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.spec.SecretKeySpec;

public final class SetupAccount {
    private SetupAccount() {}

    private static void createKeyStore(Console console, Path path) {
        char[] passphrase = null;
        char[] confirmation = null;
        byte[] key = null;
        try {
            passphrase = console.readPassword("New KeyStore passphrase: ");
            confirmation = console.readPassword("Confirm passphrase: ");
            if (passphrase == null || passphrase.length < 16 || !Arrays.equals(passphrase, confirmation)) {
                System.err.println("Use a matching KeyStore passphrase of at least 16 characters.");
                return;
            }
            key = Security.random(32);
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, passphrase);
            store.setKeyEntry("ovms-aes", new SecretKeySpec(key, "AES"), passphrase, null);
            var bytes = new java.io.ByteArrayOutputStream();
            store.store(bytes, passphrase);
            Files.write(path, bytes.toByteArray(), StandardOpenOption.CREATE_NEW);
            System.out.println("KeyStore created.");
        } catch (Exception e) {
            java.util.logging.Logger.getLogger("ovms").warning("KeyStore setup failure category: " + e.getClass().getSimpleName());
            System.err.println("Could not create the KeyStore. Check the folder and choose a new filename.");
        } finally {
            if (passphrase != null) Arrays.fill(passphrase, '\0');
            if (confirmation != null) Arrays.fill(confirmation, '\0');
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    public static void main(String[] args) {
        Console console = System.console();
        if (console != null && args.length == 2 && args[0].equals("--create-keystore")) {
            createKeyStore(console, Path.of(args[1]));
            return;
        }
        if (console == null || args.length != 2) {
            System.err.println("From a terminal, use ovms.SetupAccount --create-keystore <external-path>\n"
                    + "or ovms.SetupAccount <username> <security_admin|receptionist|host>.");
            return;
        }
        char[] password = null;
        char[] confirmation = null;
        char[] setupPassword = null;
        byte[] secret = null;
        try {
            OfficeService.Role role = OfficeService.Role.valueOf(args[1].toUpperCase(Locale.ROOT));
            password = console.readPassword("New staff password: ");
            confirmation = console.readPassword("Confirm password: ");
            if (password == null || !Arrays.equals(password, confirmation)) {
                System.err.println("The passwords must match.");
                return;
            }
            Database db = new Database();
            OfficeService service = new OfficeService(db);
            secret = role == OfficeService.Role.SECURITY_ADMIN ? Security.random(20) : null;
            setupPassword = console.readPassword("MySQL ovms_setup password: ");
            if (setupPassword == null || setupPassword.length == 0) return;
            try (var connection = DriverManager.getConnection(db.url, "ovms_setup", new String(setupPassword))) {
                service.insertAccount(connection, args[0], password, role, secret);
            }
            System.out.println("Account created: " + OfficeService.accountName(args[0]));
            if (secret != null) {
                System.out.println("In your authenticator, add a time-based account with this setup key:");
                System.out.println(Security.base32(secret));
            }
        } catch (OfficeService.Rejected e) {
            System.err.println(e.getMessage());
        } catch (Exception e) {
            java.util.logging.Logger.getLogger("ovms").warning("Account setup failure category: " + e.getClass().getSimpleName());
            System.err.println("Account setup failed. Check the role and the project setup guide.");
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (confirmation != null) Arrays.fill(confirmation, '\0');
            if (setupPassword != null) Arrays.fill(setupPassword, '\0');
            if (secret != null) Arrays.fill(secret, (byte) 0);
        }
    }
}
