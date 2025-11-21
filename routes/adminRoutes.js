import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { io, pool, sendMail, authenticateJWT } from "../server.js"; // only these
import { logAction } from "../utils.js";       // assuming utils.js contains logAction()
import sendEmail from "../email/sendEmail.js"; // your email function
import { recoveryHistory } from "../data/recovery.js"; // import directly from data

const router = express.Router();

// ===================== ADMIN LOGIN =====================
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1 AND role='admin'",
      [username]
    );

    if (result.rows.length === 0)
      return res.status(401).json({ message: "Invalid email or password" });

    const admin = result.rows[0];
    const validPass = await bcrypt.compare(password, admin.password);

    if (!validPass)
      return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: admin.id, role: admin.role },
      process.env.JWT_SECRET || "secret123",
      { expiresIn: "2h" }
    );

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error("❌ Admin login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ===================== USER MANAGEMENT =====================

// Get all users (admin only)
router.get("/users", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, first_name, last_name, email, role, active FROM users ORDER BY id"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Error fetching users" });
  }
});

// Toggle user active status
router.patch("/users/:id/toggle", authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "UPDATE users SET active = NOT active WHERE id=$1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });

    logAction("USER_TOGGLE", result.rows[0]);
    io.emit("updateUsers", result.rows[0]); // push update to frontend
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error toggling user status:", err);
    res.status(500).json({ message: "Error toggling user status" });
  }
});

// Reset user password
router.patch("/users/:id/reset", authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
    const tempPassword = "changeme";
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    const result = await pool.query(
      "UPDATE users SET password=$1 WHERE id=$2 RETURNING email",
      [hashedPassword, id]
    );

    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });

    logAction("USER_RESET", { userId: id });
    res.json({ message: "Password reset for user", tempPassword });
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).json({ message: "Error resetting password" });
  }
});

// Update recovery status
router.patch("/recovery/:id/status", authenticateJWT, async (req, res) => {
  try {
    const { status, assignedTo } = req.body;
    const recovery = recoveryHistory.find(r => r.id == req.params.id);

    if (!recovery) return res.status(404).json({ message: "Recovery not found" });

    const validStatuses = ["Pending", "In Progress", "Completed", "Rejected"];
    if (status && !validStatuses.includes(status))
      return res.status(400).json({ message: "Invalid status value" });

    if (status) recovery.status = status;
    if (assignedTo) recovery.assignedTo = assignedTo;
    recovery.updatedAt = new Date();

    logAction("RECOVERY_UPDATE", { id: recovery.id, status, assignedTo });
    io.emit("recoveryUpdate", recovery);

    if (recovery.userEmail) {
      await sendEmail({
        to: recovery.userEmail,
        subject: "Your Recovery Request Status Updated",
        html: `
          <p>Hello ${recovery.user || "User"},</p>
          <p>Your recovery request <strong>${recovery.type}</strong> status has been updated to: <strong>${status}</strong>.</p>
          ${assignedTo ? `<p>Assigned To: ${assignedTo}</p>` : ""}
          <p>Submitted At: ${new Date(recovery.submittedAt).toLocaleString()}</p>
          <p>Thank you,<br/>Phantom Recovery Team</p>
        `,
      });
    }

    res.json({ message: "Recovery status updated successfully", recovery });
  } catch (err) {
    console.error("❌ Error updating recovery status:", err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
