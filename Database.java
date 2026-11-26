package ovms;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.sql.*;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Properties;

final class Database {
    final String url;
    final String user;
    final String password;
    final byte[] key;
    final ZoneId officeZone;

    Database() throws IOException {
        Properties config = new Properties();
        Path path = Path.of(System.getProperty("ovms.config", "ovms.properties"));
        if (Files.exists(path)) {
            try (var input = Files.newInputStream(path)) {
                config.load(input);
            }
        }
        url = config.getProperty("db.url",
                "jdbc:mysql://127.0.0.1:3306/ovms?sslMode=REQUIRED&connectionTimeZone=UTC&connectTimeout=5000&socketTimeout=10000");
        user = config.getProperty("db.user", "ovms_app");
        password = config.getProperty("db.password", "");
        key = loadKey(path, config);
        officeZone = ZoneId.of(config.getProperty("office.timezone", "Asia/Qatar"));
        if (!url.startsWith("jdbc:mysql:") || password.isBlank() || (!user.matches("[a-z][a-z0-9_]{2,31}") || user.equals("root"))) {
            throw new IllegalStateException("Invalid runtime database configuration.");
        }
    }

    // SR-04 / T-02: Load the existing AES-256 key from an external Java KeyStore.
    private static byte[] loadKey(Path configPath, Properties config) throws IOException {
        String location = config.getProperty("security.keystore", "");
        String password = System.getenv("OVMS_KEYSTORE_PASSWORD");
        if (password == null) password = config.getProperty("security.keystore.password", "");
        if (location.isBlank() || password.isBlank())
            throw new IOException("KeyStore configuration is missing.");

        Path path = configPath.toAbsolutePath().getParent().resolve(location).normalize();
        char[] unlock = password.toCharArray();
        try (var input = Files.newInputStream(path)) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(input, unlock);
            if (store.getKey("ovms-aes", unlock) instanceof javax.crypto.SecretKey secret
                    && "AES".equals(secret.getAlgorithm())) {
                byte[] encoded = secret.getEncoded();
                if (encoded != null && encoded.length == 32) return encoded;
            }
            throw new IOException("Missing AES-256 KeyStore entry.");
        } catch (GeneralSecurityException e) {
            throw new IOException("Could not unlock the KeyStore.", e);
        } finally {
            Arrays.fill(unlock, '\0');
        }
    }

    Connection open() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    interface Transaction<T> {
        T run(Connection connection) throws SQLException;
    }

    // SR-08: Commit the business change and corresponding audit event together.
    <T> T transaction(Transaction<T> work) throws SQLException {
        try (Connection connection = open()) {
            // SR-08: Serialize blocklist lookups with concurrent insertions.
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            connection.setAutoCommit(false);
            try {
                T result = work.run(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException e) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    e.addSuppressed(rollbackFailure);
                }
                throw e;
            }
        }
    }
}
