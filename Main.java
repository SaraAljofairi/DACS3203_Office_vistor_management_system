package ovms;

import java.awt.*;
import java.awt.print.PrinterJob;
import java.io.IOException;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.logging.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import static ovms.OfficeService.BlockReason;
import static ovms.OfficeService.OverrideReason;
import static ovms.OfficeService.Role;
import static ovms.OfficeService.Status;

@SuppressWarnings("serial")
public final class Main extends JFrame {
    private static final Logger LOG = Logger.getLogger("ovms");
    private OfficeService service;
    private JTable visits;
    private JTextField search;
    private JComboBox<String> filter;
    private java.util.List<OfficeService.Visit> currentVisits = java.util.List.of();

    private interface Action { void run() throws Exception; }
    private record Credentials(char[] password, String code) {}

    private Main() {
        super("Office Visitor Management System");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(730, 430));
        showLogin();
        new Timer(1000, e -> {
            if (service != null && service.expired()) {
                service.logout();
                showLogin();
                message("Your session was locked after 10 minutes of inactivity.");
            }
        }).start();
        setLocationRelativeTo(null);
    }

    public static void main(String[] args) {
        try {
            FileHandler handler = new FileHandler(
                    Path.of(System.getProperty("java.io.tmpdir"), "ovms-%g.log").toString(), 16384, 2, true);
            handler.setFormatter(new SimpleFormatter());
            LOG.addHandler(handler);
            LOG.setUseParentHandlers(false);
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            LOG.warning("Startup preferences unavailable: " + e.getClass().getSimpleName());
        }
        SwingUtilities.invokeLater(() -> {
            new Main().setVisible(true);
            System.out.println("OVMS Swing login window opened.");
        });
    }

    private void showLogin() {
        currentVisits = java.util.List.of();
        JTextField username = field(32);
        JPasswordField password = new JPasswordField(23);
        JTextField code = field(6);
        JPanel form = form();
        row(form, "Username", username);
        row(form, "Password", password);
        row(form, "Authenticator code (Only for security admin)", code);

        JButton login = button("Sign in", () -> {
            char[] entered = password.getPassword();
            password.setText("");
            String otp = code.getText().strip();
            code.setText("");
            try {
                if (service == null) service = configuredService();
                OfficeService.Staff user = service.login(username.getText(), entered, otp);
                showWorkspace(user);
            } finally {
                Arrays.fill(entered, '\0');
            }
        });
        JPanel page = new JPanel(new GridBagLayout());
        JPanel card = new JPanel(new BorderLayout(0, 18));
        card.add(heading("Office Visitor Management System"), BorderLayout.NORTH);
        card.add(form, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        actions.add(login);
        card.add(actions, BorderLayout.SOUTH);
        page.add(card);
        setContentPane(page);
        getRootPane().setDefaultButton(login);
        revalidate();
        repaint();
        SwingUtilities.invokeLater(username::requestFocusInWindow);
    }

    private static OfficeService configuredService() {
        try {
            return new OfficeService(new Database());
        } catch (IOException | RuntimeException e) {
            LOG.warning("Configuration could not be loaded: " + e.getClass().getSimpleName());
            throw new OfficeService.Rejected("Application setup is incomplete. See the project README.");
        }
    }

    private void showWorkspace(OfficeService.Staff user) {
        JPanel page = new JPanel(new BorderLayout(0, 14));
        page.setBorder(BorderFactory.createEmptyBorder(16, 18, 16, 18));
        JPanel top = new JPanel(new BorderLayout());
        top.add(heading("Office Visitor Management System"), BorderLayout.WEST);
        JPanel identity = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        identity.add(new JLabel(user.username() + "  |  " + roleLabel(user.role())));
        identity.add(button("Sign out", () -> {
            service.logout();
            showLogin();
        }));
        top.add(identity, BorderLayout.EAST);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Search visits", visitsPanel(user.role()));
        if (user.role() == Role.RECEPTIONIST) tabs.addTab("Register visitor", registerPanel());
        if (user.role() == Role.SECURITY_ADMIN) {
            tabs.addTab("Staff accounts", staffPanel());
            tabs.addTab("Blocked visitors", blockPanel());
            tabs.addTab("Audit log", auditPanel());
        }
        page.add(top, BorderLayout.NORTH);
        page.add(tabs, BorderLayout.CENTER);
        setContentPane(page);
        getRootPane().setDefaultButton(null);
        setSize(Math.max(getWidth(), 960), Math.max(getHeight(), 570));
        revalidate();
        repaint();
        run(this::refreshVisits);
    }

    private JPanel visitsPanel(Role role) {
        JPanel page = new JPanel(new BorderLayout(8, 12));
        page.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        search = field(22);
        filter = new JComboBox<>(new String[] {"All statuses", "PENDING", "APPROVED", "REJECTED", "CHECKED_IN", "CHECKED_OUT"});
        if (role == Role.HOST) filter.setSelectedItem("PENDING");
        JPanel criteria = new JPanel(new FlowLayout(FlowLayout.LEFT));
        criteria.add(new JLabel("Visitor name"));
        criteria.add(search);
        criteria.add(filter);
        criteria.add(button("Search / refresh", this::refreshVisits));
        search.addActionListener(e -> run(this::refreshVisits));
        filter.addActionListener(e -> run(this::refreshVisits));
        visits = table("Visit #", "Visitor", "Masked ID", "Host", "Date", "Purpose", "Status");
        visits.setAutoCreateRowSorter(true);
        page.add(criteria, BorderLayout.NORTH);
        page.add(new JScrollPane(visits), BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        if (role == Role.HOST) {
            actions.add(button("Approve", () -> decide(true)));
            actions.add(button("Reject", () -> decide(false)));
        } else {
            if (role == Role.RECEPTIONIST) actions.add(button("Issue / print pass", this::pass));
            actions.add(button("Check in with code", this::checkIn));
            actions.add(button("Check out", () -> {
                service.checkOut(selectedVisit());
                refreshVisits();
            }));
            if (role == Role.SECURITY_ADMIN) {
                actions.add(button("Override check-in", () -> {
                    long visit = selectedVisit();
                    OverrideReason reason = chooseReason("Check-in override", OverrideReason.values());
                    if (reason == null) return;
                    Credentials credentials = reauthPrompt();
                    if (credentials == null) return;
                    service.overrideCheckIn(visit, reason, credentials.password(), credentials.code());
                    refreshVisits();
                }));
            }
        }
        page.add(actions, BorderLayout.SOUTH);
        return page;
    }

    private void refreshVisits() throws SQLException {
        Status status = filter.getSelectedIndex() == 0 ? null : Status.valueOf((String) filter.getSelectedItem());
        currentVisits = service.search(search.getText(), status);
        DefaultTableModel model = model(visits);
        model.setRowCount(0);
        for (OfficeService.Visit visit : currentVisits) {
            model.addRow(new Object[] {visit.id(), visit.name(), visit.maskedId(), visit.host(), visit.date(),
                    visit.purpose(), visit.status()});
        }
    }

    private long selectedVisit() {
        int row = visits.getSelectedRow();
        if (row < 0) throw new OfficeService.Rejected("Select a visit first.");
        return currentVisits.get(visits.convertRowIndexToModel(row)).id();
    }

    private void decide(boolean approved) throws SQLException {
        long visit = selectedVisit();
        service.decide(visit, approved);
        refreshVisits();
        message("Visit #" + visit + (approved ? " approved." : " rejected."));
    }

    private JPanel registerPanel() {
        JPanel form = form();
        JTextField name = field(28);
        JPasswordField identity = new JPasswordField(28);
        JTextField visitDate = field(10);
        visitDate.setText(service.today().toString());
        JTextField purpose = field(28);
        JComboBox<OfficeService.Host> hosts = new JComboBox<>();
        row(form, "Visitor name", name);
        row(form, "Visitor ID", identity);
        row(form, "Visit date (YYYY-MM-DD)", visitDate);
        row(form, "Purpose", purpose);
        row(form, "Assigned host", hosts);
        Action load = () -> {
            hosts.removeAllItems();
            for (OfficeService.Host host : service.hosts()) hosts.addItem(host);
        };
        row(form, "", button("Refresh hosts", load));
        row(form, "", button("Submit for approval", () -> {
            OfficeService.Host host = (OfficeService.Host) hosts.getSelectedItem();
            if (host == null) throw new OfficeService.Rejected("Select an active host.");
            LocalDate date;
            try {
                String input = visitDate.getText().strip();
                if (!input.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}"))
                    throw new OfficeService.Rejected("Enter a date in YYYY-MM-DD format.");
                date = LocalDate.parse(input);
            } catch (DateTimeParseException e) {
                throw new OfficeService.Rejected("Enter a date in YYYY-MM-DD format.");
            }
            char[] number = identity.getPassword();
            try {
                long visit = service.register(name.getText(), new String(number), host.id(), date, purpose.getText());
                name.setText("");
                identity.setText("");
                purpose.setText("");
                refreshVisits();
                message("Visit #" + visit + " is pending host approval.");
            } finally {
                Arrays.fill(number, '\0');
            }
        }));
        run(load);
        return dock(form);
    }

    private void pass() throws Exception {
        long visit = selectedVisit();
        int answer = JOptionPane.showConfirmDialog(this,
                "Issue a pass for visit #" + visit + "? An earlier code for this visit will stop working.",
                "Issue visitor pass", JOptionPane.OK_CANCEL_OPTION);
        if (answer != JOptionPane.OK_OPTION) return;
        OfficeService.Pass pass = service.issuePass(visit);
        String text = "OFFICE VISITOR PASS\n\nVisit #" + pass.visitId() + "\nPass code: " + pass.code()
                + "\nExpires: " + pass.expires().format(java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm z"));
        JTextArea preview = new JTextArea(text, 6, 42);
        preview.setEditable(false);
        int print = JOptionPane.showOptionDialog(this, new JScrollPane(preview), "Visitor pass",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, new String[] {"Print", "Close"}, "Close");
        if (print == 0) {
            PrinterJob job = PrinterJob.getPrinterJob();
            job.setJobName("Office visitor pass");
            job.setPrintable(preview.getPrintable(null, null));
            if (job.printDialog()) service.printPass(pass, job::print);
        }
    }

    private void checkIn() throws SQLException {
        String code = JOptionPane.showInputDialog(this, "Enter the visitor pass code");
        if (code == null) return;
        long visit = service.checkIn(code);
        refreshVisits();
        message("Visit #" + visit + " checked in.");
    }

    private JPanel staffPanel() {
        JPanel form = form();
        JTextField username = field(25);
        JPasswordField password = new JPasswordField(25);
        JComboBox<Role> role = new JComboBox<>(new Role[] {Role.RECEPTIONIST, Role.HOST});
        row(form, "New username", username);
        row(form, "New password (at least 12 characters)", password);
        row(form, "Role", role);
        row(form, "", button("Create staff account", () -> {
            Credentials credentials = reauthPrompt();
            if (credentials == null) return;
            char[] entered = password.getPassword();
            password.setText("");
            service.createStaff(username.getText(), entered, (Role) role.getSelectedItem(),
                    credentials.password(), credentials.code());
            username.setText("");
            message("Staff account created.");
        }));
        return dock(form);
    }

    private JPanel blockPanel() {
        JPanel page = new JPanel(new BorderLayout(0, 12));
        JPanel form = form();
        JPasswordField identity = new JPasswordField(24);
        JTable blocks = table("Reference", "Reason");
        Action load = () -> {
            DefaultTableModel model = model(blocks);
            model.setRowCount(0);
            for (OfficeService.Block block : service.blocks())
                model.addRow(new Object[] {block.reference(), block.reason()});
        };
        row(form, "Visitor ID", identity);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 4));
        for (boolean add : new boolean[] {true, false}) {
            actions.add(button(add ? "Add block" : "Remove block", () -> {
                BlockReason reason = add
                        ? chooseReason("Add block", BlockReason.SECURITY_INCIDENT, BlockReason.ACCESS_POLICY_VIOLATION)
                        : chooseReason("Remove block", BlockReason.BLOCK_NO_LONGER_REQUIRED, BlockReason.BLOCK_ENTERED_IN_ERROR);
                if (reason == null) return;
                Credentials credentials = reauthPrompt();
                if (credentials == null) return;
                char[] number = identity.getPassword();
                try {
                    service.changeBlock(new String(number), reason, add, credentials.password(), credentials.code());
                    identity.setText("");
                    load.run();
                } finally {
                    Arrays.fill(number, '\0');
                }
            }));
        }
        actions.add(button("Refresh list", load));
        row(form, "", actions);
        page.add(form, BorderLayout.NORTH);
        page.add(new JScrollPane(blocks), BorderLayout.CENTER);
        return page;
    }

    @SafeVarargs
    private final <T extends Enum<T>> T chooseReason(String title, T... reasons) {
        Object[] labels = Arrays.stream(reasons).map(reason ->
                reason.name().toLowerCase(java.util.Locale.ROOT).replace('_', ' ')).toArray();
        int selection = JOptionPane.showOptionDialog(this, "Select the reason to record in the audit log.", title,
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, labels, labels[0]);
        return selection < 0 ? null : reasons[selection];
    }

    private JPanel auditPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JTable table = table("Timestamp (UTC)", "Actor #", "Event", "Visit #", "Outcome", "Detail");
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(button("Load recent audit events", () -> {
            DefaultTableModel model = model(table);
            model.setRowCount(0);
            for (OfficeService.Audit event : service.recentAudit())
                model.addRow(new Object[] {event.when(), event.actor(), event.action(), event.visit(), event.outcome(), event.detail()});
        }));
        panel.add(actions, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private Credentials reauthPrompt() {
        JPanel panel = form();
        JPasswordField password = new JPasswordField(22);
        JTextField code = field(6);
        row(panel, "Password", password);
        row(panel, "New authenticator code", code);
        int answer = JOptionPane.showConfirmDialog(this, panel, "Confirm your identity", JOptionPane.OK_CANCEL_OPTION);
        char[] entered = password.getPassword();
        password.setText("");
        if (answer == JOptionPane.OK_OPTION) return new Credentials(entered, code.getText().strip());
        Arrays.fill(entered, '\0');
        return null;
    }

    private void run(Action action) {
        try {
            action.run();
        } catch (OfficeService.Rejected e) {
            message(e.getMessage());
            if (e.getMessage().equals("Please sign in again.")) showLogin();
        } catch (SQLException e) {
            e.printStackTrace();
            LOG.log(Level.WARNING, "Database operation failed. SQLState={0}, vendorCode={1}",
                    new Object[] {e.getSQLState(), e.getErrorCode()});
            message("Database operation failed. Check that MySQL is running and the project is configured.");
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Operation failed: {0}", e.getClass().getName());
            message("The operation could not be completed.");
        }
    }

    private void message(String message) {
        JOptionPane.showMessageDialog(this, message, getTitle(), JOptionPane.INFORMATION_MESSAGE);
    }

    private JButton button(String text, Action action) {
        JButton button = new JButton(text);
        button.addActionListener(e -> run(action));
        return button;
    }

    private static JLabel heading(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 20f));
        return label;
    }

    private static JTextField field(int columns) { return new JTextField(columns); }

    private static JPanel form() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        return panel;
    }

    private static void row(JPanel panel, String text, JComponent input) {
        GridBagConstraints label = new GridBagConstraints();
        label.gridx = 0;
        label.gridy = panel.getComponentCount() / 2;
        label.anchor = GridBagConstraints.LINE_START;
        label.insets = new Insets(6, 4, 6, 16);
        JLabel caption = new JLabel(text);
        caption.setLabelFor(input);
        panel.add(caption, label);
        GridBagConstraints field = (GridBagConstraints) label.clone();
        field.gridx = 1;
        field.weightx = 1;
        field.fill = GridBagConstraints.HORIZONTAL;
        panel.add(input, field);
    }

    private static JPanel dock(JPanel form) {
        JPanel page = new JPanel(new BorderLayout());
        page.add(form, BorderLayout.NORTH);
        return page;
    }

    private static JTable table(String... columns) {
        JTable table = new JTable(new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        });
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        return table;
    }

    private static DefaultTableModel model(JTable table) { return (DefaultTableModel) table.getModel(); }

    private static String roleLabel(Role role) {
        return switch (role) {
            case RECEPTIONIST -> "Receptionist";
            case HOST -> "Host";
            case SECURITY_ADMIN -> "Security administrator";
        };
    }
}
