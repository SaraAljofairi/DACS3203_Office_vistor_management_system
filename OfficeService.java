package ovms;

import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.*;
import java.util.*;

final class OfficeService {
    enum Role { RECEPTIONIST, HOST, SECURITY_ADMIN }
    enum Status { PENDING, APPROVED, REJECTED, CHECKED_IN, CHECKED_OUT }
    enum OverrideReason { PASS_UNREADABLE, PASS_LOST, CHECK_IN_EQUIPMENT_UNAVAILABLE }
    enum BlockReason { SECURITY_INCIDENT, ACCESS_POLICY_VIOLATION, BLOCK_NO_LONGER_REQUIRED, BLOCK_ENTERED_IN_ERROR }

    record Host(long id, String username) {
        @Override public String toString() { return username; }
    }
    record Visit(long id, String name, String maskedId, String host, LocalDate date, String purpose, Status status) {}
    record Pass(long visitId, String code, ZonedDateTime expires) {}
    record Block(String reference, String reason) {}
    record Audit(LocalDateTime when, Long actor, String action, Long visit, String outcome, String detail) {}
    record Staff(long id, String username, Role role) {}
    private record Account(Staff staff, String hash, byte[] totp, long lastStep, int failures,
                           LocalDateTime lockedUntil, boolean active) {}
    static final class Rejected extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Rejected(String message) { super(message); }
    }

    private static final Duration IDLE_LIMIT = Duration.ofMinutes(10);
    private static final String DUMMY_HASH = Security.passwordHash("unused-value-for-login-timing".toCharArray());
    private final Database db;
    private final Security security;
    private final Clock clock;
    private Staff session;
    private Instant lastActivity;

    OfficeService(Database db) {
        this(db, Clock.systemUTC());
    }

    OfficeService(Database db, Clock clock) {
        this.db = db;
        this.clock = clock;
        security = new Security(db.key);
    }

    LocalDate today() {
        return officeNow().toLocalDate();
    }

    Staff login(String username, char[] password, String code) throws SQLException {
        logout();
        Staff staff = authenticate(username, password, code, "LOGIN");
        session = staff;
        lastActivity = clock.instant();
        return staff;
    }

    void logout() {
        session = null;
        lastActivity = null;
    }

    boolean expired() {
        return session != null && !clock.instant().isBefore(lastActivity.plus(IDLE_LIMIT));
    }

    private Staff authorize(Role... roles) throws SQLException {
        Staff staff = session;
        if (staff == null || expired()) {
            logout();
            auditOutside(staff == null ? null : staff.id(), "PERMISSION_DENIED", null, "DENIED", "SESSION_REQUIRED");
            throw new Rejected("Please sign in again.");
        }

        // SR-01 / T-02: Apply the role check in the service before any data operation.
        if (!Arrays.asList(roles).contains(staff.role()) || !isActive(staff)) {
            auditOutside(staff.id(), "PERMISSION_DENIED", null, "DENIED", null);
            throw new Rejected("This action is unavailable for your role.");
        }
        lastActivity = clock.instant();
        return staff;
    }

    private boolean isActive(Staff staff) throws SQLException {
        try (Connection connection = db.open();
             PreparedStatement query = statement(connection,
                     "SELECT id FROM users WHERE id=? AND username=? AND role=? AND active=TRUE",
                     staff.id(), staff.username(), staff.role().name());
             ResultSet row = query.executeQuery()) {
            return row.next();
        }
    }

    private Staff authenticate(String rawUsername, char[] password, String code, String action) throws SQLException {
        String username = rawUsername != null && rawUsername.length() <= 40 ? rawUsername.strip().toLowerCase(Locale.ROOT) : "";
        try {
            Staff result = db.transaction(connection -> {
                Account account = username.matches("[a-z][a-z0-9._-]{2,31}") ? account(connection, username) : null;
                LocalDateTime now = utcNow();
                boolean locked = account != null && account.lockedUntil() != null
                        && now.isBefore(account.lockedUntil());
                boolean hashMatches = Security.passwordInput(password)
                        && Security.passwordMatches(password, account == null ? DUMMY_HASH : account.hash());
                long acceptedStep = -1;
                boolean valid = account != null && account.active() && !locked && hashMatches
                        && (!"REAUTHENTICATE".equals(action) || account.staff().role() == Role.SECURITY_ADMIN);
                // T-08 / T-09: MFA, replay prevention and account lockout for privileged operations.
                if (valid && account.staff().role() == Role.SECURITY_ADMIN) {
                    if (account.totp() != null && code != null && code.length() == 6) {
                        byte[] secret = security.decrypt(account.totp(), "totp:" + username);
                        try {
                            acceptedStep = Security.matchedStep(secret, code, clock.instant().getEpochSecond() / 30,
                                    account.lastStep());
                        } finally {
                            Arrays.fill(secret, (byte) 0);
                        }
                    }
                    valid = acceptedStep >= 0;
                }
                Long actor = account == null ? null : account.staff().id();
                if (!valid) {
                    if (account != null && account.active() && !locked) {
                        int failures = account.lockedUntil() == null ? account.failures() + 1 : 1;
                        update(connection, "UPDATE users SET failures=?, locked_until=? WHERE id=?",
                                failures, failures >= 5 ? now.plusMinutes(15) : null, actor);
                    }
                    audit(connection, actor, action, null, "DENIED", locked ? "LOCKED" : null);
                    return null;
                }
                update(connection, "UPDATE users SET failures=0, locked_until=NULL, last_totp_step=? WHERE id=?",
                        acceptedStep, actor);
                audit(connection, actor, action, null, "SUCCESS", null);
                return account.staff();
            });
            if (result == null) throw new Rejected("Sign-in failed. Check your credentials or try again later.");
            return result;
        } finally {
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    private Account account(Connection connection, String username) throws SQLException {
        try (PreparedStatement query = statement(connection, """
                SELECT id, username, role, password_hash, totp_secret, last_totp_step, failures, locked_until, active
                FROM users WHERE username=? FOR UPDATE
                """, username); ResultSet row = query.executeQuery()) {
            if (!row.next()) return null;
            Staff staff = new Staff(row.getLong("id"), row.getString("username"), Role.valueOf(row.getString("role")));
            return new Account(staff, row.getString("password_hash"), row.getBytes("totp_secret"),
                    row.getLong("last_totp_step"), row.getInt("failures"),
                    row.getObject("locked_until", LocalDateTime.class), row.getBoolean("active"));
        }
    }

    private Staff reauthenticate(char[] password, String code) throws SQLException {
        Staff admin = authorize(Role.SECURITY_ADMIN);
        return authenticate(admin.username(), password, code, "REAUTHENTICATE");
    }

    void createStaff(String username, char[] password, Role role, char[] currentPassword, String code) throws SQLException {
        try {
            Staff admin = reauthenticate(currentPassword, code);
            if (role != Role.RECEPTIONIST && role != Role.HOST) throw new Rejected("Choose Receptionist or Host.");
            db.transaction(connection -> {
                insertAccount(connection, username, password, role, null);
                audit(connection, admin.id(), "STAFF_CREATED", null, "SUCCESS", role.name());
                return null;
            });
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(currentPassword, '\0');
        }
    }

    // First privileged account is provisioned by a local MySQL administrator, via SetupAccount.
    static String accountName(String value) {
        String username = value != null && value.length() <= 40 ? value.strip() : "";
        if (!username.matches("[a-zA-Z][a-zA-Z0-9._-]{2,31}"))
            throw new Rejected("Use 3–32 letters, digits, periods, underscores or hyphens. Start with a letter.");
        return username.toLowerCase(Locale.ROOT);
    }

    void insertAccount(Connection connection, String rawUsername, char[] password, Role role, byte[] secret)
            throws SQLException {
        String username = accountName(rawUsername);
        if (role == null || (role == Role.SECURITY_ADMIN) != (secret != null)
                || (secret != null && secret.length != 20))
            throw new Rejected("This account configuration is unavailable.");
        if (!Security.acceptablePassword(username, password))
            throw new Rejected("Use a unique password of 12–128 characters without the username.");
        try {
            String hash = Security.passwordHash(password);
            if (secret == null) {
                update(connection, "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                        username, hash, role.name());
            } else {
                update(connection, "INSERT INTO users(username,password_hash,role,totp_secret) VALUES(?,?,?,?)",
                        username, hash, role.name(), security.encrypt(secret, "totp:" + username));
            }
        } catch (SQLIntegrityConstraintViolationException e) {
            throw new Rejected("That username is already in use.");
        }
    }

    List<Host> hosts() throws SQLException {
        authorize(Role.RECEPTIONIST);
        try (Connection connection = db.open();
             PreparedStatement query = statement(connection,
                     "SELECT id,username FROM users WHERE role='HOST' AND active=TRUE ORDER BY username");
             ResultSet rows = query.executeQuery()) {
            List<Host> hosts = new ArrayList<>();
            while (rows.next()) hosts.add(new Host(rows.getLong(1), rows.getString(2)));
            return hosts;
        }
    }

    long register(String name, String identity, long host, LocalDate date, String purpose) throws SQLException {
        Staff actor = authorize(Role.RECEPTIONIST);
        String cleanName = checkedText(name, 100, "[\\p{L}\\p{M} .’'\\-]+", "visitor name");
        String cleanPurpose = checkedText(purpose, 200, "[\\p{L}\\p{M}\\p{N}\\p{P}\\p{Zs}]+", "purpose");
        String cleanId = identity(identity);
        LocalDate today = officeNow().toLocalDate();
        if (date == null || date.isBefore(today) || date.isAfter(today.plusYears(1)))
            throw new Rejected("Choose a visit date from today through one year from today.");

        requirePositiveId(host);
        long result = db.transaction(connection -> {
            if (blocked(connection, security.fingerprint(cleanId))) {
                audit(connection, actor.id(), "VISIT_REGISTERED", null, "DENIED", "BLOCKED");
                return -1L;
            }
            try (PreparedStatement check = statement(connection,
                    
                "SELECT id FROM users WHERE id=? AND role='HOST' AND active=TRUE LOCK IN SHARE MODE", host);
                 ResultSet found = check.executeQuery()) {
                if (!found.next()) throw new Rejected("Select an active host.");
            }

            // SR-04 / T-02 / T-04: Persist a separate masked suffix and encrypt the full ID.
            long visitor = insertId(connection,
                    "INSERT INTO visitors(name,identity_cipher,identity_last4,identity_purge_at) VALUES(?,?,?,?)",
                    cleanName, security.encrypt(cleanId.getBytes(StandardCharsets.US_ASCII), "visitor-id"),
                    cleanId.substring(cleanId.length() - 4), utcNow().plusDays(30).minusHours(1));
            long visit = insertId(connection,
                    "INSERT INTO visits(visitor_id,host_id,created_by,visit_date,purpose) VALUES(?,?,?,?,?)",
                    visitor, host, actor.id(), date, cleanPurpose);
            audit(connection, actor.id(), "VISIT_REGISTERED", visit, "SUCCESS", null);
            return visit;
        });
        if (result < 0) throw new Rejected("Registration was declined. Contact security.");
        return result;
    }

    List<Visit> search(String name, Status status) throws SQLException {
        Staff actor = authorize(Role.RECEPTIONIST, Role.HOST, Role.SECURITY_ADMIN);
        String search = name != null && name.length() <= 100 ? name.strip() : null;
        if (search == null || !search.matches("[\\p{L}\\p{M} .’'\\-]*"))
            throw new Rejected("Search using a visitor name of up to 100 characters.");

        // SR-01: The database query for a host is always scoped to that host's user ID.
        String sql = """
                SELECT v.id, p.name, CASE WHEN p.identity_purge_at > UTC_TIMESTAMP() THEN p.identity_last4 END,
                       u.username, v.visit_date, v.purpose, v.status
                FROM visits v JOIN visitors p ON p.id=v.visitor_id JOIN users u ON u.id=v.host_id
                WHERE p.name LIKE ? AND (? IS NULL OR v.status=?) AND (? IS NULL OR v.host_id=?)
                ORDER BY v.id DESC LIMIT 200
                """;
        String state = status == null ? null : status.name();
        Long host = actor.role() == Role.HOST ? actor.id() : null;
        try (Connection connection = db.open(); PreparedStatement query = statement(connection, sql,
                "%" + search + "%", state, state, host, host); ResultSet rows = query.executeQuery()) {
            List<Visit> visits = new ArrayList<>();
            while (rows.next()) {
                String last4 = rows.getString(3);
                visits.add(new Visit(rows.getLong(1), rows.getString(2), last4 == null ? "" : "••••" + last4,
                        rows.getString(4), rows.getObject(5, LocalDate.class), rows.getString(6),
                        Status.valueOf(rows.getString(7))));
            }
            return visits;
        }
    }

    void decide(long visit, boolean approve) throws SQLException {
        Staff actor = authorize(Role.HOST);
        requirePositiveId(visit);
        Status state = approve ? Status.APPROVED : Status.REJECTED;
        boolean changed = db.transaction(connection -> {
            // SR-01 / SR-08 / T-01: Ownership and pending state are checked in one atomic update.
            int count = update(connection, """
                    UPDATE visits SET status=?, decided_at=?
                    WHERE id=? AND host_id=? AND status='PENDING'
                    """, state.name(), utcNow(), visit, actor.id());
            audit(connection, actor.id(), "HOST_DECISION", visit, count == 1 ? "SUCCESS" : "DENIED", state.name());
            return count == 1;
        });
        if (!changed) throw new Rejected("Only the assigned host can decide a pending request.");
    }

    Pass issuePass(long visit) throws SQLException {
        Staff actor = authorize(Role.RECEPTIONIST);
        requirePositiveId(visit);
        String code = HexFormat.of().withUpperCase().formatHex(Security.random(16));
        Pass issued = db.transaction(connection -> {
            try (PreparedStatement query = statement(connection, """
                    SELECT v.status, v.visit_date, p.identity_cipher, p.identity_purge_at
                    FROM visits v JOIN visitors p ON p.id=v.visitor_id WHERE v.id=? FOR UPDATE
                    """, visit); ResultSet row = query.executeQuery()) {
                LocalDate today = officeNow().toLocalDate();
                if (row.next() && "APPROVED".equals(row.getString(1))
                        && today.equals(row.getObject(2, LocalDate.class))
                        && allowedIdentity(connection, row.getBytes(3), row.getObject(4, LocalDateTime.class))) {
                    // SR-02 / SR-03: Store the verifier and establish expiration at office midnight.
                    ZonedDateTime expires = today.plusDays(1).atStartOfDay(db.officeZone);
                    update(connection, "UPDATE visits SET pass_hash=?,pass_expires=? WHERE id=?",
                            Security.passHash(code), LocalDateTime.ofInstant(expires.toInstant(), ZoneOffset.UTC), visit);
                    audit(connection, actor.id(), "PASS_ISSUED", visit, "SUCCESS", null);
                    System.out.println("TEST VISITOR PASS CODE: " + code);
                    return new Pass(visit, code, expires);
                }
            }
            audit(connection, actor.id(), "PASS_ISSUED", visit, "DENIED", null);
            return null;
        });
        if (issued == null) throw new Rejected("A pass requires an approved, eligible visit scheduled for today.");
        return issued;
    }

    @FunctionalInterface
    interface PassPrinter {
        void submit() throws java.awt.print.PrinterException;
    }

    // SR-06: Record the export before releasing the pass to a printer.
    void printPass(Pass pass, PassPrinter printer) throws SQLException, java.awt.print.PrinterException {
        Staff actor = authorize(Role.RECEPTIONIST);
        if (pass == null || pass.visitId() <= 0 || pass.code() == null || !pass.code().matches("[0-9A-F]{32}"))
            throw new Rejected("Select a valid visitor pass.");

        boolean valid = db.transaction(connection -> {
            boolean eligible;
            try (PreparedStatement query = statement(connection, """
                    SELECT v.pass_expires,p.identity_cipher,p.identity_purge_at
                    FROM visits v JOIN visitors p ON p.id=v.visitor_id
                    WHERE v.id=? AND v.pass_hash=? AND v.status='APPROVED' FOR UPDATE OF v
                    """, pass.visitId(), Security.passHash(pass.code()));
                 ResultSet row = query.executeQuery()) {
                eligible = row.next() && unexpired(row.getObject(1, LocalDateTime.class))
                        && allowedIdentity(connection, row.getBytes(2), row.getObject(3, LocalDateTime.class));
            }
            audit(connection, actor.id(), "PASS_PRINT", pass.visitId(), eligible ? "REQUESTED" : "DENIED", null);
            return eligible;
        });
        if (!valid) throw new Rejected("This visitor pass is no longer eligible for printing.");
        try {
            printer.submit();
        } catch (java.awt.print.PrinterException | RuntimeException failure) {
            try {
                auditOutside(actor.id(), "PASS_PRINT", pass.visitId(), "FAILED", null);
            } catch (SQLException auditFailure) {
                failure.addSuppressed(auditFailure);
            }
            throw failure;
        }
        auditOutside(actor.id(), "PASS_PRINT", pass.visitId(), "SUBMITTED", null);
    }

    long checkIn(String rawCode) throws SQLException {
        Staff actor = authorize(Role.RECEPTIONIST, Role.SECURITY_ADMIN);
        String input = rawCode != null && rawCode.length() <= 40 ? rawCode.strip() : "";
        if (!input.matches("[0-9a-fA-F]{32}")) {
            auditOutside(actor.id(), "CHECK_IN", null, "DENIED", null);
            throw new Rejected("Enter the 32-character pass code.");
        }
        String code = input.toUpperCase(Locale.ROOT);
        long visit = db.transaction(connection -> {
            try (PreparedStatement query = statement(connection, """
                    SELECT v.id,v.pass_expires,p.identity_cipher,p.identity_purge_at
                    FROM visits v JOIN visitors p ON p.id=v.visitor_id
                    WHERE v.pass_hash=? AND v.status='APPROVED' FOR UPDATE 
                    """, Security.passHash(code)); ResultSet row = query.executeQuery()) {
                if (row.next() && unexpired(row.getObject(2, LocalDateTime.class))
                        && allowedIdentity(connection, row.getBytes(3), row.getObject(4, LocalDateTime.class))) {
                    long id = row.getLong(1);
                    recordCheckIn(connection, id);
                    audit(connection, actor.id(), "CHECK_IN", id, "SUCCESS", null);
                    return id;
                }
            }
            audit(connection, actor.id(), "CHECK_IN", null, "DENIED", null);
            return -1L;
        });
        if (visit < 0) throw new Rejected("The pass is invalid or the visit is ineligible for check-in.");
        return visit;
    }

    void checkOut(long visit) throws SQLException {
        Staff actor = authorize(Role.RECEPTIONIST, Role.SECURITY_ADMIN);
        requirePositiveId(visit);
        boolean changed = db.transaction(connection -> {
            int count = update(connection, """
                    UPDATE visits SET status='CHECKED_OUT',checked_out_at=?
                    WHERE id=? AND status='CHECKED_IN'
                    """, utcNow(), visit);
            audit(connection, actor.id(), "CHECK_OUT", visit, count == 1 ? "SUCCESS" : "DENIED", null);
            return count == 1;
        });
        if (!changed) throw new Rejected("Select a checked-in visit.");
    }

    void overrideCheckIn(long visit, OverrideReason reason, char[] password, String code) throws SQLException {
        Staff actor;
        try {
            actor = reauthenticate(password, code);
        } finally {
            Arrays.fill(password, '\0');
        }
        requirePositiveId(visit);
        if (reason == null) throw new Rejected("Select an override reason.");
        boolean changed = db.transaction(connection -> {
            try (PreparedStatement query = statement(connection, """
                    SELECT p.identity_cipher,p.identity_purge_at,v.visit_date FROM visits v
                    JOIN visitors p ON p.id=v.visitor_id WHERE v.id=? AND v.status='APPROVED' FOR UPDATE OF v
                    """, visit); ResultSet row = query.executeQuery()) {
                if (row.next() && officeNow().toLocalDate().equals(row.getObject(3, LocalDate.class))
                        && allowedIdentity(connection, row.getBytes(1), row.getObject(2, LocalDateTime.class))) {
                    recordCheckIn(connection, visit);
                    audit(connection, actor.id(), "CHECK_IN_OVERRIDE", visit, "SUCCESS", reason.name());
                    return true;
                }
            }
            audit(connection, actor.id(), "CHECK_IN_OVERRIDE", visit, "DENIED", reason.name());
            return false;
        });
        if (!changed) throw new Rejected("Override requires an approved, eligible visit scheduled for today.");
    }

    private void recordCheckIn(Connection connection, long visit) throws SQLException {
        update(connection, "UPDATE visits SET status='CHECKED_IN',checked_in_at=? WHERE id=?", utcNow(), visit);
    }

    void changeBlock(String visitorId, BlockReason reason, boolean add, char[] password, String code) throws SQLException {
        Staff actor;
        try {
            actor = reauthenticate(password, code);
        } finally {
            Arrays.fill(password, '\0');
        }
        byte[] fingerprint = security.fingerprint(identity(visitorId));
        if (reason == null || add != (reason == BlockReason.SECURITY_INCIDENT
                || reason == BlockReason.ACCESS_POLICY_VIOLATION))
            throw new Rejected("Select a reason for this blocklist change.");
        boolean changed = db.transaction(connection -> {
            int count;
            try {
                count = add ? update(connection, """
                        INSERT INTO blocked_visitors(fingerprint,reason,created_by) VALUES(?,?,?)
                        """, fingerprint, reason.name(), actor.id())
                        : update(connection, "DELETE FROM blocked_visitors WHERE fingerprint=?", fingerprint);
            } catch (SQLIntegrityConstraintViolationException e) {
                count = 0;
            }
            audit(connection, actor.id(), add ? "BLOCK_ADDED" : "BLOCK_REMOVED", null,
                    count == 1 ? "SUCCESS" : "DENIED", reason.name());
            return count == 1;
        });
        if (!changed) throw new Rejected(add ? "This visitor is already blocked." : "No matching block was found.");
    }

    List<Block> blocks() throws SQLException {
        authorize(Role.SECURITY_ADMIN);
        try (Connection connection = db.open(); PreparedStatement query = statement(connection,
                "SELECT LEFT(HEX(fingerprint),12),reason FROM blocked_visitors ORDER BY created_at DESC LIMIT 200");
             ResultSet rows = query.executeQuery()) {
            List<Block> blocks = new ArrayList<>();
            while (rows.next()) blocks.add(new Block(rows.getString(1), rows.getString(2)));
            return blocks;
        }
    }

    List<Audit> recentAudit() throws SQLException {
        Staff actor = authorize(Role.SECURITY_ADMIN);
        auditOutside(actor.id(), "AUDIT_VIEWED", null, "SUCCESS", null);
        try (Connection connection = db.open(); PreparedStatement query = statement(connection, """
                SELECT event_at,actor_id,event_type,visit_id,outcome,detail FROM audit_events ORDER BY id DESC LIMIT 200
                """); ResultSet rows = query.executeQuery()) {
            List<Audit> events = new ArrayList<>();
            while (rows.next()) events.add(new Audit(rows.getObject(1, LocalDateTime.class),
                    rows.getObject(2, Long.class), rows.getString(3), rows.getObject(4, Long.class),
                    rows.getString(5), rows.getString(6)));
            return events;
        }
    }

    private boolean allowedIdentity(Connection connection, byte[] cipher, LocalDateTime purgeAt) throws SQLException {
        if (cipher == null || purgeAt == null || !utcNow().isBefore(purgeAt)) return false;
        byte[] raw = security.decrypt(cipher, "visitor-id");
        try {
            return !blocked(connection, security.fingerprint(new String(raw, StandardCharsets.US_ASCII)));
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private boolean blocked(Connection connection, byte[] fingerprint) throws SQLException {
        try (PreparedStatement query = statement(connection,
                "SELECT fingerprint FROM blocked_visitors WHERE fingerprint=? FOR UPDATE", fingerprint);
             ResultSet row = query.executeQuery()) {
            return row.next();
        }
    }

    private static String identity(String value) {
        String id = value != null && value.length() <= 24 ? value.strip() : "";
        if (!id.matches("[a-zA-Z0-9]{4,24}")) throw new Rejected("Use 4–24 letters or digits for the visitor ID.");
        return id.toUpperCase(Locale.ROOT);
    }

    private static String checkedText(String value, int limit, String pattern, String label) {
        String clean = value != null && value.length() <= limit ? value.strip() : "";
        if (clean.isEmpty() || !clean.matches(pattern))
            throw new Rejected("Enter a valid " + label + " of up to " + limit + " characters.");
        return clean;
    }

    private static void requirePositiveId(long id) {
        if (id <= 0) throw new Rejected("Select a valid record.");
    }

    private boolean unexpired(LocalDateTime expires) {
        return expires != null && utcNow().isBefore(expires);
    }

    private ZonedDateTime officeNow() {
        return clock.instant().atZone(db.officeZone);
    }

    private LocalDateTime utcNow() {
        return LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    private void auditOutside(Long actor, String type, Long visit, String outcome, String detail) throws SQLException {
        try (Connection connection = db.open()) {
            audit(connection, actor, type, visit, outcome, detail);
        }
    }

    // SR-06 / T-07: Append-only logging. Never pass credentials, full IDs or pass codes to this method.
    private void audit(Connection connection, Long actor, String type, Long visit, String outcome, String detail)
            throws SQLException {
        update(connection, """
                INSERT INTO audit_events(event_at,actor_id,event_type,visit_id,outcome,detail) VALUES(?,?,?,?,?,?)
                """, utcNow(), actor, type, visit, outcome, detail);
    }

    private static PreparedStatement statement(Connection connection, String sql, Object... values) throws SQLException {
        PreparedStatement statement = connection.prepareStatement(sql);
        try {
            for (int i = 0; i < values.length; i++) statement.setObject(i + 1, values[i]);
            return statement;
        } catch (SQLException e) {
            statement.close();
            throw e;
        }
    }

    private static int update(Connection connection, String sql, Object... values) throws SQLException {
        try (PreparedStatement statement = statement(connection, sql, values)) {
            return statement.executeUpdate();
        }
    }

    private static long insertId(Connection connection, String sql, Object... values) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            for (int i = 0; i < values.length; i++) statement.setObject(i + 1, values[i]);
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) return keys.getLong(1);
                throw new SQLException("Missing generated ID");
            }
        }
    }
}
