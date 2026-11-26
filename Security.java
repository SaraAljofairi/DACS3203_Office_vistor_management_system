package ovms;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

final class Security {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int ITERATIONS = 600_000;
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final Set<String> COMMON = Set.of(
            "password", "passwordpassword", "passw0rd", "qwerty", "qwertyuiop", "qwertyuiopasdf",
            "letmein", "admin", "administrator", "changeme", "welcome", "iloveyou", "abcdefghijkl",
            "abc", "asdfghjkl", "asdfghjklqwerty", "zxcvbnm", "qazwsx", "trustno", "princess",
            "monkey", "dragon", "football", "baseball", "sunshine", "superman", "starwars",
            "pokemon", "liverpool", "blink", "myspace", "default", "guest", "secret", "security",
            "office", "ovms", "visitor", "test", "demo");
    private final byte[] key;

    Security(byte[] key) {
        this.key = key.clone();
    }

    static byte[] random(int bytes) {
        byte[] buffer = new byte[bytes];
        RANDOM.nextBytes(buffer);
        return buffer;
    }

    // T-09: Screen locally at account creation and reset. Credentials stay on this workstation.
    static boolean acceptablePassword(String username, char[] password) {
        if (!passwordInput(password)) return false;
        String normalized = java.text.Normalizer.normalize(java.nio.CharBuffer.wrap(password),
                java.text.Normalizer.Form.NFKC).strip().toLowerCase(Locale.ROOT);
        String base = normalized.replaceAll("[\\p{N}\\p{P}\\p{S}\\p{Zs}]+$", "");
        String simplified = base.replace('@', 'a').replace('0', 'o').replace('1', 'i')
                .replace('3', 'e').replace('4', 'a').replace('$', 's').replace('5', 's').replace('7', 't');
        return normalized.length() >= 12 && !base.isEmpty()
                && !normalized.contains(username.toLowerCase(Locale.ROOT))
                && !COMMON.contains(normalized) && !COMMON.contains(base) && !COMMON.contains(simplified)
                && !normalized.matches("(.{1,4})\\1+");
    }

    static boolean passwordInput(char[] password) {
        return password != null && password.length >= 12 && password.length <= 128
                && passwordInputCharacters(password);
    }

    private static boolean passwordInputCharacters(char[] password) {
        return java.util.regex.Pattern.matches("[\\p{L}\\p{M}\\p{N}\\p{P}\\p{S}\\p{Zs}]+",
                java.nio.CharBuffer.wrap(password));
    }

    // Login baseline: PBKDF2-HMAC-SHA256 and random salt per user.
    static String passwordHash(char[] password) {
        byte[] salt = random(16);
        return ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(derive(password, salt, ITERATIONS));
    }

    static boolean passwordMatches(char[] password, String encoded) {
        String[] parts = encoded.split(":", -1);
        if (parts.length != 3 || !Integer.toString(ITERATIONS).equals(parts[0])
                || parts[1].length() != 24 || parts[2].length() != 44) return false;
        byte[] salt = Base64.getDecoder().decode(parts[1]);
        byte[] expected = Base64.getDecoder().decode(parts[2]);
        if (salt.length != 16 || expected.length != 32) return false;
        byte[] actual = derive(password, salt, ITERATIONS);
        try {
            return MessageDigest.isEqual(expected, actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int rounds) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, rounds, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } finally {
            spec.clearPassword();
        }
    }

    // SR-04 / T-02: Each encrypted value gets a new random GCM nonce.
    byte[] encrypt(byte[] data, String context) {
        byte[] nonce = random(12);
        byte[] encrypted = crypt(Cipher.ENCRYPT_MODE, data, nonce, context);
        return ByteBuffer.allocate(nonce.length + encrypted.length).put(nonce).put(encrypted).array();
    }

    byte[] decrypt(byte[] data, String context) {
        return crypt(Cipher.DECRYPT_MODE, Arrays.copyOfRange(data, 12, data.length),
                Arrays.copyOf(data, 12), context);
    }

    private byte[] crypt(int mode, byte[] data, byte[] nonce, String context) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    byte[] fingerprint(String visitorId) {
        byte[] fingerprintKey = hmac("HmacSHA256", key, "OVMS blocklist key".getBytes(StandardCharsets.UTF_8));
        return hmac("HmacSHA256", fingerprintKey, visitorId.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] passHash(String code) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(code.getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static long matchedStep(byte[] secret, String code, long current, long previous) {
        if (!code.matches("[0-9]{6}")) return -1;
        for (long step = current - 1; step <= current + 1; step++) {
            if (step > previous && MessageDigest.isEqual(code.getBytes(StandardCharsets.US_ASCII),
                    totp(secret, step).getBytes(StandardCharsets.US_ASCII))) return step;
        }
        return -1;
    }

    // Privileged login baseline: RFC 6238, 30-second time step, HMAC-SHA1 and six digits.
    static String totp(byte[] secret, long step) {
        byte[] hash = hmac("HmacSHA1", secret, ByteBuffer.allocate(8).putLong(step).array());
        int offset = hash[hash.length - 1] & 15;
        int value = ByteBuffer.wrap(hash, offset, 4).getInt() & Integer.MAX_VALUE;
        return String.format(Locale.ROOT, "%06d", value % 1_000_000);
    }

    static String base32(byte[] data) {
        StringBuilder encoded = new StringBuilder();
        int bits = 0;
        int buffer = 0;
        for (byte value : data) {
            buffer = (buffer << 8) | (value & 255);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                encoded.append(BASE32.charAt((buffer >> bits) & 31));
            }
        }
        if (bits > 0) encoded.append(BASE32.charAt((buffer << (5 - bits)) & 31));
        return encoded.toString();
    }

    private static byte[] hmac(String algorithm, byte[] secret, byte[] value) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(secret, algorithm));
            return mac.doFinal(value);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
