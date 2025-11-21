// ---------------- Dependencies ----------------
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import nodemailer from "nodemailer";
import fs from "fs";
import http from "http";
import { Server } from "socket.io";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import { fileURLToPath } from "url";
import adminRoutes from "./routes/adminRoutes.js";

// ✅ Define __dirname for ES modules (must come before using it)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- Initialize ----------------
dotenv.config();
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// ---------------- Middlewares ----------------
app.use(cors({ origin: process.env.CORS_ORIGIN || "*", credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ 
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this', 
  resave: false, 
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/images', express.static(path.join(__dirname, '..', 'images')));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/admin", adminRoutes);

// JWT Authentication Middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403); // forbidden if token invalid
      }
      req.user = user;
      next(); // pass control to next middleware/route
    });
  } else {
    res.sendStatus(401); // unauthorized if no token
  }
}


// =================== Admin Seeder ==================
async function createAdminUser() {
  const adminEmail = "admin@phantomrecovery.com";
  const adminPassword = "supersecure123";

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1 AND role='admin'",
      [adminEmail]
    );

    if (result.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await pool.query(
        `INSERT INTO users (first_name, last_name, email, password, role, active)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        ["Admin", "User", adminEmail, hashedPassword, "admin", true]
      );
      console.log(`✅ Admin user created: ${adminEmail} / ${adminPassword}`);
    } else {
      console.log("Admin user already exists, skipping creation.");
    }
  } catch (err) {
    console.error("❌ Failed to create admin user:", err);
  }
}

// ================================================================
// 🔗 Database Connection
// ================================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.query('SELECT NOW()')
  .then(res => console.log('DB connected:', res.rows[0]))
  .catch(err => console.error('DB connection error:', err));

// ---------------- Nodemailer Setup ----------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendMail({ subject, text, to }) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: to || process.env.EMAIL_TO,
    subject,
    text,
  };
  return transporter.sendMail(mailOptions);
}

// ---------------- In-Memory Storage ----------------
let recoveryHistory = [];
let tickets = [];
let users = [
  { id: 1, username: "alice", email: "alice@example.com", role: "client", active: true },
  { id: 2, username: "bob", email: "bob@example.com", role: "analyst", active: true },
  { id: 3, username: "admin", email: "admin@example.com", role: "admin", active: true },
];
let systemConfig = {
  emailAlerts: true,
  pushNotifications: true,
  twoFA: false,
  allowedAdmins: ["admin"],
};
let otpStore = {}; // { email: { code, expiresAt } }
let withdrawalCodes = {};
let stats = { activeUsers: 0, recoveries: 0 };

// =============================================================
// ---------------- Wallet JSON Data ----------------
const DATA_FILE = path.join(__dirname, "wallets.json");

function loadWallets() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(DATA_FILE, JSON.stringify([], null, 2));
      return [];
    }
    const data = fs.readFileSync(DATA_FILE, "utf8");
    return JSON.parse(data);
  } catch (err) {
    console.error("Error loading wallets:", err);
    return [];
  }
}

function saveWallets(wallets) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(wallets, null, 2));
}

// ---------------- Audit Logging ----------------
const logFile = path.join(__dirname, "audit.log");
function logAction(action, details) {
  const timestamp = new Date().toISOString();
  const entry = `[${timestamp}] ${action} - ${JSON.stringify(details)}\n`;
  try {
    fs.appendFileSync(logFile, entry);
    console.log(`[${timestamp}] ACTION: ${action} | DETAILS:`, details);
  } catch (err) {
    console.error("Error writing to audit log:", err);
  }
}

// ---------------- Utility ----------------
function notifyAdmins(message) {
  io.emit("adminNotification", { message, time: new Date().toISOString() });
  sendMail({ subject: "🔔 Admin Notification", text: message }).catch(console.error);
}

function saveRecovery({ type, status, details, user }) {
  const entry = {
    id: recoveryHistory.length + 1,
    type,
    status: status || "Pending",
    details,
    user: user || "anonymous",
    submittedAt: new Date().toISOString(),
  };
  recoveryHistory.push(entry);
  logAction("RECOVERY_CREATED", entry);
  io.emit("recoveryUpdate", entry);
  notifyAdmins(`New recovery request submitted (#${entry.id}, type: ${entry.type})`);

  const failures = recoveryHistory.filter((r) => r.status === "Failed").length;
  if (failures > 5) {
    sendMail({
      subject: "🚨 Recovery Alert",
      text: `High failure rate detected: ${failures} failed recoveries.`,
    }).catch(console.error);
  }
  return entry;
}

app.get("/api/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ success: true, now: result.rows[0] });
  } catch (err) {
    console.error("DB test error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});


// =====================================================================
// ------------------------ PASSPORT STRATEGIES ------------------------
// =====================================================================

// ------------------------ GOOGLE STRATEGY ----------------------------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:5000/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  let user = users.find(u => u.email === profile.emails[0].value);
  if (!user) {
    user = {
      id: users.length + 1,
      username: profile.displayName,
      email: profile.emails[0].value,
      role: "client",
      active: true
    };
    users.push(user);
  }
  return done(null, user);
}));

// ------------------------ SERIALIZATION ------------------------------
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users.find(u => u.id === id)));

// =====================================================================
// ------------------------ OAUTH ROUTES -------------------------------
// =====================================================================

// ----- GOOGLE -----
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.redirect(`/dashboard?token=${token}`);
  }
);

// =====================================================================
// ------------------------ PUBLIC ENDPOINTS ---------------------------
// =====================================================================

// Get public stats
app.get('/api/stats', (req, res) => {
  res.json(stats);
});

// Update stats (should be protected in production)
app.post("/api/stats/update", authenticateJWT, (req, res) => {
  stats = { ...stats, ...req.body };
  io.emit("statsUpdated", stats);
  res.json({ message: "Stats updated", stats });
});

// =====================================================================
// ------------------------ AUTH ENDPOINTS -----------------------------
// =====================================================================

// Request OTP
app.post("/api/auth/request-otp", async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ message: "Email required" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { code: otp, expiresAt: Date.now() + 5 * 60 * 1000 }; // 5 mins

  try {
    await sendMail({
      to: email,
      subject: "Your Phantom Recovery OTP",
      text: `Your OTP code is: ${otp}. Expires in 5 minutes.`,
    });
    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Failed to send OTP:", err);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

app.post("/api/auth/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  
  if (!email || !otp) {
    return res.status(400).json({ message: "Email and OTP required" });
  }

  const record = otpStore[email];
  if (!record) return res.status(400).json({ message: "No OTP requested for this email" });
  if (Date.now() > record.expiresAt) return res.status(400).json({ message: "OTP expired" });
  if (record.code !== otp) return res.status(400).json({ message: "Incorrect OTP" });

  delete otpStore[email];
  res.json({ message: "OTP verified" });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = users.find((u) => u.username === email || u.email === email);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.password = hashedPassword;
    logAction("PASSWORD_RESET", { email });
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// =====================================================================
// ------------------------ REGISTER USER -----------------------------
app.post("/api/register", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Check if user exists (case-insensitive)
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE LOWER(email) = LOWER($1)",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into database
    const newUserResult = await pool.query(
      `INSERT INTO users (first_name, last_name, email, password, role, active)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, email, first_name`,
      [firstName, lastName, email, hashedPassword, "client", true]
    );

    const newUser = newUserResult.rows[0];

    // Log action and send welcome email
    logAction("USER_REGISTER", { email, id: newUser.id });
    await sendMail({
      to: email,
      subject: "Welcome to Phantom Recovery",
      text: `Hi ${firstName}, your account has been successfully created!`
    });

    console.log(`✅ New user registered: ${email}`);

    res.status(201).json({
      success: true,
      message: "Account created successfully",
      userId: newUser.id,
    });

  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ message: "Failed to create account" });
  }
});

// ------------------------ LOGIN USER -----------------------------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    // Fetch user from database
    const result = await pool.query(
      "SELECT id, email, password, role FROM users WHERE LOWER(email) = LOWER($1)",
      [email]
    );

    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: "User not found" });
    if (!user.password) return res.status(400).json({ message: "Password not set for this account" });

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Incorrect password" });

    // Generate JWT
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "24h" });

    logAction("USER_LOGIN", { email, id: user.id });
    console.log(`✅ Login successful: ${email}`);

    res.json({
      success: true,
      message: "Login successful",
      token,
      userId: user.id,
      role: user.role,
    });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: "Login failed" });
  }
});


// =====================================================================
// ------------------------ USER PROFILE & PREFERENCES ----------------
app.get("/api/user/:id", (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if(!user) return res.status(404).json({ message:"User not found" });
  res.json(user);
});

app.patch("/api/user/:id", (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if(!user) return res.status(404).json({ message:"User not found" });
  Object.assign(user, req.body);
  logAction("USER_UPDATE", { id: user.id, changes: req.body });
  res.json({ message:"Profile updated", user });
});

// ---------------------- CREATE NEW TICKET ----------------------------
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: "⚠️ All fields are required." });
    }

    // Create a ticket object
    const ticket = {
      id: tickets.length + 1,
      name,
      email,
      subject,
      message,
      resolved: false,
      createdAt: new Date().toISOString(),
    };

    tickets.push(ticket);
    logAction("NEW_TICKET_CREATED", ticket);

    // Send notification email
    await sendMail({
      subject: `[Support Ticket] ${subject}`,
      text: `New ticket received from ${name} <${email}>\n\nMessage:\n${message}`,
    });

    // Notify admin in real-time (Socket.IO)
    io.emit("adminNotification", {
      type: "new_ticket",
      message: `🎫 New ticket from ${name}: "${subject}"`,
      ticket,
    });

    return res.json({
      success: true,
      message: "✅ Your support ticket has been sent successfully!",
      ticket,
    });
  } catch (err) {
    console.error("Ticket Error:", err);
    res.status(500).json({ success: false, message: "❌ Failed to send ticket." });
  }
});

// Update ticket status
app.patch("/api/admin/tickets/:id", authenticateJWT, (req, res) => {
  const ticket = tickets.find((t) => t.id == req.params.id);
  if (!ticket) return res.status(404).json({ message: "❌ Ticket not found." });

  ticket.resolved = req.body.resolved === true;
  ticket.updatedAt = new Date().toISOString();

  logAction("TICKET_STATUS_UPDATED", ticket);

  io.emit("adminNotification", {
    type: "ticket_update",
    message: `📬 Ticket #${ticket.id} marked ${ticket.resolved ? "resolved" : "pending"}.`,
    ticket,
  });

  res.json({ success: true, message: "✅ Ticket status updated!", ticket });
});


// ------------------------ SYSTEM SETTINGS ------------------------

// Get system settings
app.get("/api/admin/settings", authenticateJWT, (req, res) => {
  res.json(systemConfig);
});

// Update system settings
app.patch("/api/admin/settings", authenticateJWT, (req, res) => {
  Object.assign(systemConfig, req.body);
  logAction("SETTINGS_UPDATE", systemConfig);
  io.emit("settingsUpdate", systemConfig); // notify frontend if needed
  res.json(systemConfig);
});
// ------------------------ RECOVERY ENDPOINTS -------------------------
// =====================================================================

// Wallet recovery
app.post("/api/recovery/wallet", async (req, res) => {
  const { seed, passwordHint, user } = req.body;
  if (!seed && !passwordHint) return res.status(400).json({ message: "⚠️ Provide seed or password hint." });

  try {
    await sendMail({
      subject: "[Recovery] Wallet Recovery Request",
      text: `Seed/Backup: ${seed || "N/A"}\nPassword Hint: ${passwordHint || "N/A"}`,
    });
    const saved = saveRecovery({ type: "Wallet Recovery", status: "Pending", details: { seed, passwordHint }, user });
    res.json({ message: "✅ Wallet recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit wallet recovery." });
  }
});

app.post("/api/recovery/key", async (req, res) => {
  const { keystore, hardware, user } = req.body;
  if (!keystore && !hardware) return res.status(400).json({ message: "⚠️ Provide keystore or hardware details." });

  try {
    await sendMail({
      subject: "[Recovery] Lost Key Recovery Request",
      text: `Keystore: ${keystore || "N/A"}\nHardware: ${hardware || "N/A"}`,
    });
    const saved = saveRecovery({ type: "Lost Key Recovery", status: "Pending", details: { keystore, hardware }, user });
    res.json({ message: "✅ Lost key recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit lost key recovery." });
  }
});

app.post("/api/recovery/transaction", async (req, res) => {
  const { txid, blockchain, notes, user } = req.body;
  if (!txid || !blockchain) return res.status(400).json({ message: "⚠️ TxID and Blockchain required." });

  try {
    await sendMail({
      subject: "[Recovery] Transaction Recovery Request",
      text: `TxID: ${txid}\nBlockchain: ${blockchain}\nNotes: ${notes || "N/A"}`,
    });
    const saved = saveRecovery({ type: "Transaction Recovery", status: "Pending", details: { txid, blockchain, notes }, user });
    res.json({ message: "✅ Transaction recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit transaction recovery." });
  }
});

app.post("/api/recovery/multichain", async (req, res) => {
  const { blockchains, coins, user } = req.body;
  if (!blockchains || !coins) return res.status(400).json({ message: "⚠️ Blockchains and Coins required." });

  try {
    await sendMail({
      subject: "[Recovery] Multi-Chain Recovery Request",
      text: `Blockchains: ${blockchains}\nCoins: ${coins}`,
    });
    const saved = saveRecovery({ type: "Multi-Chain Recovery", status: "Pending", details: { blockchains, coins }, user });
    res.json({ message: "✅ Multi-chain recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit multi-chain recovery." });
  }
});

// =====================================================================
// ------------------------ WITHDRAWAL SYSTEM --------------------------
// =====================================================================

// Request withdrawal
app.post('/api/withdraw/request', authenticateJWT, async (req, res) => {
  const { walletId, amount } = req.body;
  const userId = req.user.id;

  if (!walletId || !amount) {
    return res.status(400).json({ message: "Wallet and amount are required." });
  }

  try {
    const walletRes = await pool.query(
      "SELECT * FROM wallets WHERE id=$1 AND user_id=$2", 
      [walletId, userId]
    );
    
    const wallet = walletRes.rows[0];
    if (!wallet) {
      return res.status(404).json({ message: "Wallet not found." });
    }
    
    if (wallet.balance < amount) {
      return res.status(400).json({ message: "Insufficient balance." });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    withdrawalCodes[userId] = { code, expiresAt: Date.now() + 5*60*1000, walletId, amount }; // 5 min expiry

    // Send email
    const userRes = await pool.query("SELECT email, phone FROM users WHERE id=$1", [userId]);
    const user = userRes.rows[0];
    if (user?.email) {
      await sendMail({ to: user.email, subject: "Your Withdrawal Code", text: `Your code is: ${code}` });
    }

    // Optional: Send SMS if service available
    // if (user?.phone) await sendSMS(user.phone, `Your withdrawal code is ${code}`);

    res.json({ message: "Verification code sent to your email/SMS. Enter it to confirm withdrawal." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});

// ---------------- Confirm withdrawal (verify code & process) ----------------
app.post('/api/withdraw/confirm', authenticateJWT, async (req, res) => {
  const { walletId, amount, code } = req.body;
  const userId = req.user.id;

  // Check pending request
  const record = withdrawalCodes[userId];
  if (!record || record.walletId != walletId || record.amount != amount) {
    return res.status(400).json({ message: "No pending withdrawal request found." });
  }

  // Check expiry
  if (Date.now() > record.expiresAt) {
    delete withdrawalCodes[userId];
    return res.status(400).json({ message: "Verification code expired." });
  }

  // Check code
  if (record.code !== code) {
    return res.status(401).json({ message: "Invalid verification code." });
  }

  try {
    // Process withdrawal
    await pool.query("UPDATE wallets SET balance=balance-$1 WHERE id=$2", [amount, walletId]);
    await pool.query("INSERT INTO withdrawals (user_id, wallet_id, amount) VALUES ($1,$2,$3)", [userId, walletId, amount]);

    // Emit update to clients
    const updatedWallet = await pool.query("SELECT * FROM wallets WHERE id=$1", [walletId]);
    io.emit("walletsUpdated", updatedWallet.rows[0]);

    // Remove used code
    delete withdrawalCodes[userId];

    res.json({ message: "Withdrawal successful.", wallet: updatedWallet.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});

// ------------------------ WITHDRAWAL SYSTEM --------------------------
// =====================================================================

// Request withdrawal
app.post('/api/withdraw/request', authenticateJWT, async (req, res) => {
  const { walletId, amount } = req.body;
  const userId = req.user.id;

  if (!walletId || !amount) {
    return res.status(400).json({ message: "Wallet and amount are required." });
  }

  try {
    const walletRes = await pool.query(
      "SELECT * FROM wallets WHERE id=$1 AND user_id=$2", 
      [walletId, userId]
    );
    
    const wallet = walletRes.rows[0];
    if (!wallet) {
      return res.status(404).json({ message: "Wallet not found." });
    }
    
    if (wallet.balance < amount) {
      return res.status(400).json({ message: "Insufficient balance." });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    withdrawalCodes[userId] = { code, expiresAt: Date.now() + 5*60*1000, walletId, amount }; // 5 min expiry

    // Send email
    const userRes = await pool.query("SELECT email, phone FROM users WHERE id=$1", [userId]);
    const user = userRes.rows[0];
    if (user?.email) {
      await sendMail({ to: user.email, subject: "Your Withdrawal Code", text: `Your code is: ${code}` });
    }

    // Optional: Send SMS if service available
    // if (user?.phone) await sendSMS(user.phone, `Your withdrawal code is ${code}`);

    res.json({ message: "Verification code sent to your email/SMS. Enter it to confirm withdrawal." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});

// ---------------- Confirm withdrawal (verify code & process) ----------------
app.post('/api/withdraw/confirm', authenticateJWT, async (req, res) => {
  const { walletId, amount, code } = req.body;
  const userId = req.user.id;

  // Check pending request
  const record = withdrawalCodes[userId];
  if (!record || record.walletId != walletId || record.amount != amount) {
    return res.status(400).json({ message: "No pending withdrawal request found." });
  }

  // Check expiry
  if (Date.now() > record.expiresAt) {
    delete withdrawalCodes[userId];
    return res.status(400).json({ message: "Verification code expired." });
  }

  // Check code
  if (record.code !== code) {
    return res.status(401).json({ message: "Invalid verification code." });
  }

  try {
    // Process withdrawal
    await pool.query("UPDATE wallets SET balance=balance-$1 WHERE id=$2", [amount, walletId]);
    await pool.query("INSERT INTO withdrawals (user_id, wallet_id, amount) VALUES ($1,$2,$3)", [userId, walletId, amount]);

    // Emit update to clients
    const updatedWallet = await pool.query("SELECT * FROM wallets WHERE id=$1", [walletId]);
    io.emit("walletsUpdated", updatedWallet.rows[0]);

    // Remove used code
    delete withdrawalCodes[userId];

    res.json({ message: "Withdrawal successful.", wallet: updatedWallet.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});
// --------------------- HISTORY & LOGS -------------------------------
app.get("/api/history", (req, res) => {
  const { type, status, search, role, user } = req.query;
  let results = [...recoveryHistory];

  if (role === "client") results = results.filter((r) => r.user === user);
  else if (role === "analyst") results = results.map(({ id, type, status, submittedAt }) => ({ id, type, status, submittedAt }));

  if (type) results = results.filter((r) => r.type === type);
  if (status) results = results.filter((r) => r.status === status);
  if (search) {
    const s = search.toLowerCase();
    results = results.filter((r) =>
      r.type.toLowerCase().includes(s) ||
      JSON.stringify(r.details).toLowerCase().includes(s) ||
      r.submittedAt.toLowerCase().includes(s)
    );
  }
  res.json(results);
});

app.get("/api/history/:id", (req, res) => {
  const recovery = recoveryHistory.find((r) => r.id == req.params.id);
  if (!recovery) return res.status(404).json({ message: "Not found" });
  res.json(recovery);
});

app.get("/api/logs/download", (req, res) => res.download(logFile, "audit.log"));

// =====================================================================
// ------------------------ PAGES & AUTH -------------------------------
// ---------------- PAGES & ROUTES ----------------
const pages = [
  "index","about","analytics","contact","dashboard","history","home","login",
  "pass","profile","register","request","services","setting","support","wallet",
  "testimonials","admin","adlogin","adforget"
];

const frontendPath = path.join(__dirname, "public");
app.use(express.static(frontendPath));

pages.forEach((page) => {
  const routePath = page === "index" ? "/" : `/${page}`;
  app.get(routePath, (req, res) => {
    res.sendFile(path.join(frontendPath, `${page}.html`));
  });
});

import authRoutes from "./routes/auth.js";
app.use("/api/auth", authRoutes);

// ✅ Catch-all route for frontend
app.use((req, res, next) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// ------------------------- SERVER START ------------------------------
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));

// ---------------- WebSocket ----------------
io.on("connection", (socket) => {
  console.log("🔌 Client connected:", socket.id);
  socket.emit("initData", recoveryHistory);
});
// ---------------- EXPORTS ----------------
export { io, pool, sendMail, authenticateJWT };
