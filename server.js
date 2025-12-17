require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const pool = require("./db");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, role } = req.body;

  const allowedRoles = ["donor", "admin", "volunteer"];
  const safeRole = allowedRoles.includes(role) ? role : "donor";

  try {
    const [exists] = await pool.query("SELECT user_id FROM Users WHERE email = ?", [email]);
    if (exists.length) return res.status(409).json({ message: "Email already registered." });

    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO Users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, hashed, safeRole]
    );

    res.status(201).json({ message: "Account created successfully." });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query(
      "SELECT user_id, name, password, role FROM Users WHERE email = ?",
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

    res.json({ message: "Login successful", token, role: user.role, name: user.name });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// -------- PUBLIC LISTS --------
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
// -------- PUBLIC STATS (for homepage cards/table) --------
app.get("/api/public-stats", async (req, res) => {
  try {
    const [[row]] = await pool.query(`
      SELECT
        COALESCE((SELECT SUM(amount) FROM Donation), 0) AS totalDonations,
        COALESCE((
          SELECT COUNT(*)
          FROM Cause
          WHERE
            (start_date IS NULL OR start_date <= CURDATE())
            AND (end_date IS NULL OR end_date >= CURDATE())
        ), 0) AS activeCauses,
        COALESCE((SELECT COUNT(*) FROM Users), 0) AS registeredUsers
    `);

    res.json(row);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.get("/api/ngos", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT ngo_id AS id, name FROM NGO ORDER BY name");
    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// -------- DONATION (GUEST ALLOWED) --------
// Donation.user_id is NOT NULL, so we auto-create/find a donor user by email.
app.post("/process-donation", async (req, res) => {
  try {
    const { cause_id, cause_name, amount, name, email } = req.body;

    if (!amount || Number(amount) <= 0) {
      return res.status(400).json({ message: "Invalid amount" });
    }
    if (!email || !String(email).includes("@")) {
      return res.status(400).json({ message: "Valid email required" });
    }

    // 1) Resolve cause_id
    let resolvedCauseId = cause_id ? Number(cause_id) : null;

    if (!resolvedCauseId && cause_name) {
      const [causeRows] = await pool.query(
        "SELECT cause_id FROM Cause WHERE title = ? LIMIT 1",
        [cause_name]
      );
      if (!causeRows.length) return res.status(404).json({ message: "Cause not found" });
      resolvedCauseId = causeRows[0].cause_id;
    }

    if (!resolvedCauseId) return res.status(400).json({ message: "cause_id required" });

    // 2) Find or create user by email (role: 'donor')
    let userId;
    const [uRows] = await pool.query("SELECT user_id FROM Users WHERE email=? LIMIT 1", [email]);

    if (uRows.length) {
      userId = uRows[0].user_id;

      if (name && name.trim()) {
        await pool.query("UPDATE Users SET name=? WHERE user_id=?", [name.trim(), userId]);
      }
    } else {
      const randomPass = crypto.randomBytes(16).toString("hex");
      const hashed = await bcrypt.hash(randomPass, 10);
      const displayName = name && name.trim() ? name.trim() : "Guest Donor";

      const [ins] = await pool.query(
        "INSERT INTO Users (name, email, password, role) VALUES (?, ?, ?, ?)",
        [displayName, email, hashed, "donor"]
      );
      userId = ins.insertId;
    }

    if (!userId) {
      return res.status(500).json({ message: "Internal error: userId not resolved" });
    }

    // 3) Insert donation + link donation_cause (transaction)
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [donRes] = await conn.query(
        "INSERT INTO Donation (user_id, amount) VALUES (?, ?)",
        [userId, Number(amount)]
      );

      await conn.query(
        "INSERT INTO Donation_Cause (donation_id, cause_id, amount_allocated) VALUES (?, ?, ?)",
        [donRes.insertId, resolvedCauseId, Number(amount)]
      );

      await conn.commit();
      return res.status(201).json({ message: "Donation recorded", donationId: donRes.insertId });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (e) {
    return res.status(500).json({ message: "DB error", error: e.message });
  }
});

// Logged-in donation API
app.post("/api/donations", requireAuth, async (req, res) => {
  try {
    const { cause_id, amount } = req.body;
    if (!cause_id || !amount || Number(amount) <= 0) {
      return res.status(400).json({ message: "cause_id and valid amount required" });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [donRes] = await conn.query(
        "INSERT INTO Donation (user_id, amount) VALUES (?, ?)",
        [req.user.user_id, Number(amount)]
      );

      await conn.query(
        "INSERT INTO Donation_Cause (donation_id, cause_id, amount_allocated) VALUES (?, ?, ?)",
        [donRes.insertId, Number(cause_id), Number(amount)]
      );

      await conn.commit();
      res.status(201).json({ message: "Donation recorded", donationId: donRes.insertId });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

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

// -------- USER PROFILE --------
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
        [skills || null, availability || null, ngo_id || null, userId]
      );
    } else {
      await pool.query(
        "INSERT INTO Volunteer (user_id, skill, availability, primary_ngo_id) VALUES (?, ?, ?, ?)",
        [userId, skills || null, availability || null, ngo_id || null]
      );
    }

    res.json({ message: "Volunteer registered/updated" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.post("/api/user/submit_feedback", requireAuth, async (req, res) => {
  const { ngo_id, rating, message } = req.body;
  try {
    const userId = req.user.user_id;
    await pool.query(
      "INSERT INTO Feedback (user_id, ngo_id, rating, message) VALUES (?, ?, ?, ?)",
      [userId, ngo_id, rating, message || null]
    );
    res.json({ message: "Feedback submitted" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// -------- ADMIN: CAUSES + audit --------
app.post("/api/admin/causes", requireAuth, requireRole("admin"), async (req, res) => {
  const { ngo_id, title, goal_amount, category, start_date, end_date, description } = req.body;
  try {
    const [r] = await pool.query(
      `INSERT INTO Cause (ngo_id, title, description, goal_amount, category, start_date, end_date)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [ngo_id, title, description, goal_amount, category || null, start_date || null, end_date || null]
    );

    await pool.query("INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)", [
      req.user.user_id,
      `Created cause #${r.insertId}: ${title}`,
    ]);

    res.status(201).json({ message: "Cause created", id: r.insertId });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.put("/api/admin/causes/:id", requireAuth, requireRole("admin"), async (req, res) => {
  const id = Number(req.params.id);
  const { ngo_id, title, goal_amount, category, start_date, end_date, description } = req.body;

  try {
    await pool.query(
      `UPDATE Cause
       SET ngo_id=?, title=?, description=?, goal_amount=?, category=?, start_date=?, end_date=?
       WHERE cause_id=?`,
      [ngo_id, title, description, goal_amount, category || null, start_date || null, end_date || null, id]
    );

    await pool.query("INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)", [
      req.user.user_id,
      `Updated cause #${id}: ${title}`,
    ]);

    res.json({ message: "Cause updated" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.delete("/api/admin/causes/:id", requireAuth, requireRole("admin"), async (req, res) => {
  const id = Number(req.params.id);
  try {
    await pool.query("DELETE FROM Cause WHERE cause_id = ?", [id]);

    await pool.query("INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)", [
      req.user.user_id,
      `Deleted cause #${id}`,
    ]);

    res.json({ message: "Deleted" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

// -------- ADMIN: DONATION update/delete + audit --------
app.put("/api/admin/donations/:id", requireAuth, requireRole("admin"), async (req, res) => {
  const id = Number(req.params.id);
  const { amount } = req.body;

  try {
    await pool.query("UPDATE Donation SET amount=? WHERE donation_id=?", [Number(amount), id]);
    await pool.query("UPDATE Donation_Cause SET amount_allocated=? WHERE donation_id=?", [
      Number(amount),
      id,
    ]);

    await pool.query("INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)", [
      req.user.user_id,
      `Updated donation #${id} amount -> ${amount}`,
    ]);

    res.json({ message: "Donation updated" });
  } catch (e) {
    res.status(500).json({ message: "DB error", error: e.message });
  }
});

app.delete("/api/admin/donations/:id", requireAuth, requireRole("admin"), async (req, res) => {
  const id = Number(req.params.id);

  try {
    await pool.query("DELETE FROM Donation_Cause WHERE donation_id=?", [id]);
    await pool.query("DELETE FROM Donation WHERE donation_id=?", [id]);

    await pool.query("INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)", [
      req.user.user_id,
      `Deleted donation #${id}`,
    ]);

    res.json({ message: "Donation deleted" });
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

// receipt placeholder
app.get("/receipts/:id", (req, res) => {
  res.send(`<h2>Receipt #${req.params.id}</h2><p>Build PDF/HTML receipt here.</p>`);
});

app.get("/", (req, res) => res.send("API running (MySQL real)"));

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on http://localhost:${process.env.PORT || 3000}`);
});
