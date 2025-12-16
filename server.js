require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // for form bodies if needed

// -------- JWT middleware --------
function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // { user_id, role }
    next();
  } catch {
    return res.status(401).json({ message: "Invalid/expired token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    next();
  };
}

// -------- AUTH --------

// Signup (stores in MySQL)
app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const [exists] = await pool.query("SELECT user_id FROM Users WHERE email = ?", [email]);
    if (exists.length) return res.status(409).json({ message: "Email already registered." });

    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO Users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, hashed, role]
    );

    res.status(201).json({ message: "Account created successfully." });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// Login (checks MySQL + returns JWT)
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query(
      "SELECT user_id, password, role FROM Users WHERE email = ?",
      [email]
    );
    if (!rows.length) return res.status(401).json({ message: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { user_id: user.user_id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({ message: "Login successful", token, role: user.role });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// -------- HOME + ADMIN --------

// Public list for home/admin
app.get("/api/causes", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        c.cause_id AS id,
        c.title,
        n.name AS ngo,
        c.description,
        c.goal_amount AS goal,
        COALESCE(SUM(dc.amount_allocated), 0) AS collected
      FROM Cause c
      JOIN NGO n ON n.ngo_id = c.ngo_id
      LEFT JOIN Donation_Cause dc ON dc.cause_id = c.cause_id
      GROUP BY c.cause_id, c.title, n.name, c.description, c.goal_amount
      ORDER BY c.cause_id DESC
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// Admin create cause (REAL insert + REAL audit)
app.post("/api/admin/causes", requireAuth, requireRole("admin"), async (req, res) => {
  const { ngo_id, title, goal_amount, category, start_date, end_date, description } = req.body;
  try {
    const [r] = await pool.query(
      `INSERT INTO Cause (ngo_id, title, description, goal_amount, category, start_date, end_date)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [ngo_id, title, description, goal_amount, category || null, start_date, end_date]
    );

    await pool.query(
      "INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)",
      [req.user.user_id, `Created cause #${r.insertId}: ${title}`]
    );

    res.status(201).json({ message: "Cause created", id: r.insertId });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// Admin delete cause
app.delete("/api/admin/causes/:id", requireAuth, requireRole("admin"), async (req, res) => {
  const id = Number(req.params.id);
  try {
    await pool.query("DELETE FROM Cause WHERE cause_id = ?", [id]);

    await pool.query(
      "INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)",
      [req.user.user_id, `Deleted cause #${id}`]
    );

    res.json({ message: "Deleted" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// -------- DONOR DASHBOARD --------

// current user profile + stats
app.get("/api/user/me", requireAuth, async (req, res) => {
  try {
    const userId = req.user.user_id;

    const [rows] = await pool.query(
      `
      SELECT 
        u.user_id,
        u.name,
        u.email,
        COALESCE(SUM(d.amount), 0) AS totalDonated,
        COALESCE(COUNT(DISTINCT dc.cause_id), 0) AS causesSupported
      FROM Users u
      LEFT JOIN Donation d ON d.user_id = u.user_id
      LEFT JOIN Donation_Cause dc ON dc.donation_id = d.donation_id
      WHERE u.user_id = ?
      GROUP BY u.user_id, u.name, u.email
      `,
      [userId]
    );

    if (!rows.length) return res.status(404).json({ message: "User not found" });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// donation history of logged-in user
app.get("/api/donations/history", requireAuth, async (req, res) => {
  try {
    const userId = req.user.user_id;

    const [rows] = await pool.query(
      `
      SELECT
        d.donation_id AS id,
        d.donation_date AS date,
        c.title AS causeTitle,
        dc.amount_allocated AS amount,
        'DB' AS method
      FROM Donation d
      JOIN Donation_Cause dc ON dc.donation_id = d.donation_id
      JOIN Cause c ON c.cause_id = dc.cause_id
      WHERE d.user_id = ?
      ORDER BY d.donation_date DESC
      `,
      [userId]
    );

    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// NGOs list (used by dashboard selects)
app.get("/api/ngos", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT ngo_id AS id, name FROM NGO ORDER BY name");
    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// update profile (logged-in user)
app.post("/api/user/update_profile", requireAuth, async (req, res) => {
  const { name, password } = req.body;
  try {
    const userId = req.user.user_id;
    if (password && password.trim()) {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query("UPDATE Users SET name = ?, password = ? WHERE user_id = ?", [
        name,
        hashed,
        userId,
      ]);
    } else {
      await pool.query("UPDATE Users SET name = ? WHERE user_id = ?", [name, userId]);
    }
    res.json({ message: "Profile updated" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// register volunteer (logged-in user)
app.post("/api/user/register_volunteer", requireAuth, async (req, res) => {
  const { skills, ngo_id, availability } = req.body;
  try {
    const userId = req.user.user_id;

    const [existing] = await pool.query("SELECT volunteer_id FROM Volunteer WHERE user_id = ?", [
      userId,
    ]);

    if (existing.length) {
      await pool.query(
        "UPDATE Volunteer SET skill = ?, availability = ?, primary_ngo_id = ? WHERE user_id = ?",
        [skills, availability || null, ngo_id, userId]
      );
    } else {
      await pool.query(
        "INSERT INTO Volunteer (user_id, skill, availability, primary_ngo_id) VALUES (?, ?, ?, ?)",
        [userId, skills, availability || null, ngo_id]
      );
    }

    res.json({ message: "Volunteer registered/updated" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// submit feedback (logged-in user)
app.post("/api/user/submit_feedback", requireAuth, async (req, res) => {
  const { ngo_id, rating, message } = req.body;
  try {
    const userId = req.user.user_id;
    await pool.query(
      "INSERT INTO Feedback (user_id, ngo_id, rating, message) VALUES (?, ?, ?, ?)",
      [userId, ngo_id, rating, message]
    );
    res.json({ message: "Feedback submitted" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// -------- REPORTS (admin-only) --------

app.get("/api/stats", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const [[stats]] = await pool.query(`
      SELECT
        COALESCE(SUM(amount), 0) AS totalFundsRaised,
        (SELECT COUNT(*) FROM Volunteer) AS activeVolunteers,
        COALESCE(MAX(amount), 0) AS highestDonation
      FROM Donation
    `);
    res.json(stats);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.get("/api/audit", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    // if your Admin table is separate, you can map admin_id differently.
    // Here we assume admin_id == Users.user_id for simplicity
    const [rows] = await pool.query(`
      SELECT
        a.log_id AS id,
        a.timestamp,
        a.admin_id AS actorId,
        u.name AS actorName,
        'ADMIN' AS actionType,
        a.action AS actionDetails
      FROM Audit_Log a
      LEFT JOIN Users u ON u.user_id = a.admin_id
      ORDER BY a.timestamp DESC
      LIMIT 100
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.get("/api/category_breakdown", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        COALESCE(c.category, 'Uncategorized') AS categoryName,
        COUNT(*) AS transactionCount,
        COALESCE(SUM(dc.amount_allocated), 0) AS totalAmount,
        COALESCE(AVG(dc.amount_allocated), 0) AS avgDonation
      FROM Donation_Cause dc
      JOIN Cause c ON c.cause_id = dc.cause_id
      GROUP BY COALESCE(c.category, 'Uncategorized')
      ORDER BY totalAmount DESC
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.get("/api/volunteer_assignments", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        u.name AS volunteerName,
        v.skill AS skillSet,
        e.description AS assignedEvent,
        e.start_date AS eventDate
      FROM Volunteer_Event ve
      JOIN Volunteer v ON v.volunteer_id = ve.volunteer_id
      JOIN Users u ON u.user_id = v.user_id
      JOIN Event e ON e.event_id = ve.event_id
      ORDER BY e.start_date DESC
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// receipt placeholder
app.get("/receipts/:id", (req, res) => {
  res.send(`<h2>Receipt #${req.params.id}</h2><p>Build PDF/HTML receipt here.</p>`);
});

app.get("/", (req, res) => res.send("API running (MySQL real)"));

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on http://localhost:${process.env.PORT || 3000}`);
});
