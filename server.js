require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const pool = require('./db');

const app = express();

// ---- middleware ----
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve ONLY the frontend (avoid exposing backend source files)
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

// ---------- auth helpers ----------
function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid/expired token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(String(req.user.role).toLowerCase())) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    return next();
  };
}

async function getStaffContext(userId) {
  const [[row]] = await pool.query(
    `SELECT staff_id, ngo_id FROM Staff WHERE user_id = ? LIMIT 1`,
    [userId]
  );
  return row || null;
}

// ---------- AUTH ----------
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, role } = req.body;

  const allowedRoles = ['user', 'admin', 'staff', 'volunteer'];
  const safeRole = allowedRoles.includes((role || '').toLowerCase()) ? role.toLowerCase() : 'user';

  try {
    const [exists] = await pool.query('SELECT user_id FROM Users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ message: 'Email already registered.' });

    const hashed = await bcrypt.hash(password, 10);
    const [ins] = await pool.query(
      'INSERT INTO Users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashed, safeRole]
    );

    // If a staff signs up, make it explicit they still need NGO assignment in Staff table.
    return res.status(201).json({ message: 'Account created successfully.', user_id: ins.insertId });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query(
      'SELECT user_id, name, password, role FROM Users WHERE email = ?',
      [email]
    );
    if (!rows.length) return res.status(401).json({ message: 'Invalid credentials' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { user_id: user.user_id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.json({ message: 'Login successful', token, role: user.role, name: user.name, email });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// ---------- PUBLIC ----------
app.get('/api/ngos', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT ngo_id AS id, name FROM NGO ORDER BY name');
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// NOTE: Only approved causes should be visible publicly.
app.get('/api/causes', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        c.cause_id AS id,
        c.title,
        n.name AS ngo,
        c.description,
        c.goal_amount AS goal,
        c.status,
        COALESCE(SUM(dc.amount_allocated), 0) AS collected
      FROM Cause c
      JOIN NGO n ON n.ngo_id = c.ngo_id
      LEFT JOIN Donation_Cause dc ON dc.cause_id = c.cause_id
      WHERE c.status = 'approved'
      GROUP BY c.cause_id, c.title, n.name, c.description, c.goal_amount, c.status
      ORDER BY c.cause_id DESC
    `);
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.get('/api/public-stats', async (req, res) => {
  try {
    const [[row]] = await pool.query(`
      SELECT
        COALESCE((SELECT SUM(amount) FROM Donation), 0) AS totalDonations,
        COALESCE((
          SELECT COUNT(*)
          FROM Cause
          WHERE status='approved'
            AND (start_date IS NULL OR start_date <= CURDATE())
            AND (end_date IS NULL OR end_date >= CURDATE())
        ), 0) AS activecauses,
        COALESCE((SELECT COUNT(*) FROM Users), 0) AS registeredUsers
    `);

    return res.json(row);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});
// Public: causes for a specific NGO (approved only)
app.get('/api/ngos/:ngoId/causes', async (req, res) => {
  try {
    const ngoId = Number(req.params.ngoId);
    if (!ngoId) return res.status(400).json({ message: 'Invalid ngoId' });

    const [rows] = await pool.query(
      `
      SELECT cause_id AS id, title
      FROM Cause
      WHERE ngo_id = ? AND status = 'approved'
      ORDER BY cause_id DESC
      `,
      [ngoId]
    );

    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// ---------- DONATIONS ----------
// Guest donation: Donation.user_id NOT NULL, so we auto-create/find a user by email.
app.post('/process-donation', async (req, res) => {
  try {
const { cause_id, cause_name, amount, name, email, payment_method } = req.body;


    if (!amount || Number(amount) <= 0) {
      return res.status(400).json({ message: 'Invalid amount' });
    }
    if (!email || !String(email).includes('@')) {
      return res.status(400).json({ message: 'Valid email required' });
    }

    // 1) Resolve cause_id
    let resolvedCauseId = cause_id ? Number(cause_id) : null;

    if (!resolvedCauseId && cause_name) {
      const [causeRows] = await pool.query(
        'SELECT cause_id FROM Cause WHERE title = ? AND status=\'approved\' LIMIT 1',
        [cause_name]
      );
      if (!causeRows.length) return res.status(404).json({ message: 'Cause not found' });
      resolvedCauseId = causeRows[0].cause_id;
    }

    if (!resolvedCauseId) return res.status(400).json({ message: 'cause_id required' });

    // Ensure cause is approved (important when cause_id is passed directly)
    const [[cause]] = await pool.query(
      'SELECT status FROM Cause WHERE cause_id = ? LIMIT 1',
      [resolvedCauseId]
    );
    if (!cause || String(cause.status).toLowerCase() !== 'approved') {
      return res.status(400).json({ message: 'Cause is not approved for donation' });
    }

    // 2) Find or create user by email (role: 'user')
    let userId;
    const [uRows] = await pool.query('SELECT user_id FROM Users WHERE email=? LIMIT 1', [email]);

    if (uRows.length) {
      userId = uRows[0].user_id;

      if (name && name.trim()) {
        await pool.query('UPDATE Users SET name=? WHERE user_id=?', [name.trim(), userId]);
      }
    } else {
      const randomPass = crypto.randomBytes(16).toString('hex');
      const hashed = await bcrypt.hash(randomPass, 10);
      const displayName = name && name.trim() ? name.trim() : 'Anonymous';


      const [ins] = await pool.query(
        'INSERT INTO Users (name, email, password, role) VALUES (?, ?, ?, ?)',
        [displayName, email, hashed, 'user']
      );
      userId = ins.insertId;
    }

    if (!userId) {
      return res.status(500).json({ message: 'Internal error: userId not resolved' });
    }

    // 3) Insert donation + link donation_cause (transaction)
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [donRes] = await conn.query(
 'INSERT INTO Donation (user_id, amount, payment_method) VALUES (?, ?, ?)',
 [userId, Number(amount), payment_method || 'physical']
      );

      await conn.query(
        'INSERT INTO Donation_Cause (donation_id, cause_id, amount_allocated) VALUES (?, ?, ?)',
        [donRes.insertId, resolvedCauseId, Number(amount)]
      );

      await conn.commit();
      return res.status(201).json({ message: 'Donation recorded', donationId: donRes.insertId });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Logged-in donation API
app.post('/api/donations', requireAuth, async (req, res) => {
  try {
   const { cause_id, amount, payment_method } = req.body;
    if (!cause_id || !amount || Number(amount) <= 0) {
      return res.status(400).json({ message: 'cause_id and valid amount required' });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Only allow donations to approved causes
      const [[cause]] = await conn.query(
        'SELECT status FROM Cause WHERE cause_id = ? LIMIT 1',
        [Number(cause_id)]
      );
      if (!cause || String(cause.status).toLowerCase() !== 'approved') {
        await conn.rollback();
        return res.status(400).json({ message: 'Cause is not approved for donation' });
      }

      const [donRes] = await conn.query(
'INSERT INTO Donation (user_id, amount, payment_method) VALUES (?, ?, ?)',
[req.user.user_id, Number(amount), payment_method || 'physical']
      );

      await conn.query(
        'INSERT INTO Donation_Cause (donation_id, cause_id, amount_allocated) VALUES (?, ?, ?)',
        [donRes.insertId, Number(cause_id), Number(amount)]
      );

      await conn.commit();
      return res.status(201).json({ message: 'Donation recorded', donationId: donRes.insertId });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.get('/api/donations/history', requireAuth, async (req, res) => {
  try {
    const userId = req.user.user_id;
    const [rows] = await pool.query(
      `
      SELECT
        d.donation_id AS id,
        d.donation_date AS date,
        c.title AS causeTitle,
        dc.amount_allocated AS amount,
        d.payment_method
      FROM Donation d
      JOIN Donation_Cause dc ON dc.donation_id = d.donation_id
      JOIN Cause c ON c.cause_id = dc.cause_id
      WHERE d.user_id = ?
      ORDER BY d.donation_date DESC
      `,
      [userId]
    );
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.get('/api/db-health', async (req, res) => {
  try {
    const [r] = await pool.query('SELECT 1 AS ok');
    res.json({ ok: true, result: r });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- USER PROFILE ----------
app.get('/api/user/me', requireAuth, async (req, res) => {
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
    if (!rows.length) return res.status(404).json({ message: 'User not found' });
    return res.json(rows[0]);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.post('/api/user/update_profile', requireAuth, async (req, res) => {
  const { name, password } = req.body;
  try {
    const userId = req.user.user_id;
    if (password && password.trim()) {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('UPDATE Users SET name = ?, password = ? WHERE user_id = ?', [
        name,
        hashed,
        userId,
      ]);
    } else {
      await pool.query('UPDATE Users SET name = ? WHERE user_id = ?', [name, userId]);
    }
    return res.json({ message: 'Profile updated' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Backwards compatible alias (old frontend used /api/volunteer) - SAFE implementation (no router hacks)
app.post('/api/volunteer', requireAuth, async (req, res) => {
  const { skills, ngo_id, availability } = req.body;
  try {
    const userId = req.user.user_id;

    const [existing] = await pool.query('SELECT volunteer_id FROM Volunteer WHERE user_id = ?', [
      userId,
    ]);

    if (existing.length) {
      await pool.query(
        'UPDATE Volunteer SET skill = ?, availability = ?, primary_ngo_id = ? WHERE user_id = ?',
        [skills || null, availability || null, ngo_id || null, userId]
      );
    } else {
      await pool.query(
        'INSERT INTO Volunteer (user_id, skill, availability, primary_ngo_id) VALUES (?, ?, ?, ?)',
        [userId, skills || null, availability || null, ngo_id || null]
      );
    }

    return res.json({ message: 'Volunteer registered/updated' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});
// ---------- FEEDBACK VIEW (Admin + Staff) ----------
// Admin: sees all feedback, can filter by ngo_id and q (name/email/message)
// Staff: sees feedback ONLY for their own NGO (from Staff table)
app.get('/api/feedbacks', requireAuth, requireRole('admin', 'staff'), async (req, res) => {
  try {
    const role = String(req.user.role || '').toLowerCase();
    const q = (req.query.q || '').toString().trim();
    const ngoIdParam = req.query.ngo_id ? Number(req.query.ngo_id) : null;

    let ngoId = ngoIdParam;

    // Staff forced to their NGO
    if (role === 'staff') {
      const ctx = await getStaffContext(req.user.user_id);
      if (!ctx) {
        return res.status(404).json({ message: 'Staff record not found (assign NGO first).' });
      }
      ngoId = ctx.ngo_id;
    }

    const params = [];
    const where = [];

    if (ngoId) {
      where.push('f.ngo_id = ?');
      params.push(ngoId);
    }

    if (q) {
      where.push('(u.name LIKE ? OR u.email LIKE ? OR f.message LIKE ?)');
      const like = `%${q}%`;
      params.push(like, like, like);
    }
const sql = `
  SELECT
    f.feedback_id AS id,
    f.ngo_id,
    n.name AS ngo_name,
    f.rating,
    f.message,
    f.timestamp,
    u.user_id AS user_id,
    u.name AS user_name,
    u.email AS user_email,
    u.role AS user_role
  FROM Feedback f
  JOIN Users u ON u.user_id = f.user_id
  JOIN NGO n ON n.ngo_id = f.ngo_id
  ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
  ORDER BY f.timestamp DESC
  LIMIT 1000
`;


    const [rows] = await pool.query(sql, params);
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.post('/api/user/register_volunteer', requireAuth, async (req, res) => {
  const { skills, ngo_id, availability } = req.body;
  try {
    const userId = req.user.user_id;

    const [existing] = await pool.query('SELECT volunteer_id FROM Volunteer WHERE user_id = ?', [
      userId,
    ]);

    if (existing.length) {
      await pool.query(
        'UPDATE Volunteer SET skill = ?, availability = ?, primary_ngo_id = ? WHERE user_id = ?',
        [skills || null, availability || null, ngo_id || null, userId]
      );
    } else {
      await pool.query(
        'INSERT INTO Volunteer (user_id, skill, availability, primary_ngo_id) VALUES (?, ?, ?, ?)',
        [userId, skills || null, availability || null, ngo_id || null]
      );
    }

    return res.json({ message: 'Volunteer registered/updated' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.post('/api/user/submit_feedback', requireAuth, requireRole('user'), async (req, res) => {

  const { ngo_id, rating, message } = req.body;
  try {
    const userId = req.user.user_id;
    const r = Number(rating);
    if (!Number.isFinite(r) || r < 1 || r > 5) {
      return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    await pool.query('INSERT INTO Feedback (user_id, ngo_id, rating, message) VALUES (?, ?, ?, ?)', [
      userId,
      ngo_id,
      r,
      message || null,
    ]);
    return res.json({ message: 'Feedback submitted' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// ---------- STAFF (DB-backed) ----------
app.get('/api/staff/me', requireAuth, requireRole('staff'), async (req, res) => {
  try {
    const ctx = await getStaffContext(req.user.user_id);
    if (!ctx) return res.status(404).json({ message: 'Staff record not found. Assign this staff to an NGO in Staff table.' });

    const [[ngo]] = await pool.query('SELECT ngo_id, name FROM NGO WHERE ngo_id=?', [ctx.ngo_id]);
    return res.json({ staff_id: ctx.staff_id, ngo });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Staff: create NGO and auto-assign this staff to it
app.post('/api/staff/ngos', requireAuth, requireRole('staff'), async (req, res) => {
  try {
    const { name, description, phone, city } = req.body;

    if (!name || !description) {
      return res.status(400).json({ message: 'name and description required' });
    }

    // NOTE: If your NGO table does NOT have phone/city columns, remove them from both SQL + params.
    const [ngoRes] = await pool.query(
      `INSERT INTO NGO (name, description, phone, city) VALUES (?, ?, ?, ?)`,
      [name.trim(), description.trim(), phone || null, city || null]
    );

    const ngoId = ngoRes.insertId;

    // Upsert Staff assignment for this user
    const [[existing]] = await pool.query(
      `SELECT staff_id FROM Staff WHERE user_id = ? LIMIT 1`,
      [req.user.user_id]
    );

    if (existing) {
      await pool.query(`UPDATE Staff SET ngo_id = ? WHERE user_id = ?`, [ngoId, req.user.user_id]);
    } else {
      await pool.query(`INSERT INTO Staff (user_id, ngo_id) VALUES (?, ?)`, [req.user.user_id, ngoId]);
    }

    return res.status(201).json({ message: 'NGO created and assigned to staff', ngo_id: ngoId });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Staff: view feedback for their NGO
app.get('/api/staff/feedbacks', requireAuth, requireRole('staff'), async (req, res) => {
  try {
    const ctx = await getStaffContext(req.user.user_id);
    if (!ctx) return res.status(404).json({ message: 'Staff record not found (assign NGO first).' });

    const [rows] = await pool.query(
      `
      SELECT
        f.feedback_id AS id,
        f.timestamp,
        f.rating,
        f.message,
        u.name  AS user_name,
        u.email AS user_email,
        u.role  AS user_role
      FROM Feedback f
      LEFT JOIN Users u ON u.user_id = f.user_id
      WHERE f.ngo_id = ?
      ORDER BY f.timestamp DESC
      LIMIT 300
      `,
      [ctx.ngo_id]
    );

    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Staff: list volunteers for staff's NGO (by primary_ngo_id)
app.get('/api/staff/volunteers', requireAuth, requireRole('staff'), async (req, res) => {
  try {
    const ctx = await getStaffContext(req.user.user_id);
    if (!ctx) return res.status(404).json({ message: 'Staff record not found (assign NGO first).' });

    const [rows] = await pool.query(
      `
      SELECT
        v.volunteer_id AS id,
        u.name,
        v.skill,
        v.availability
      FROM Volunteer v
      JOIN Users u ON u.user_id = v.user_id
      WHERE v.primary_ngo_id = ?
      ORDER BY u.name
      LIMIT 500
      `,
      [ctx.ngo_id]
    );

    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Staff creates an event (pending)
app.post('/api/staff/events', requireAuth, requireRole('staff'), async (req, res) => {
  const { title, description, location, start_datetime, end_datetime } = req.body;
  try {
    const ctx = await getStaffContext(req.user.user_id);
    if (!ctx) return res.status(404).json({ message: 'Staff record not found (assign NGO first).' });
    if (!title || !start_datetime) return res.status(400).json({ message: 'title and start_datetime required' });

    const [r] = await pool.query(
      `INSERT INTO Event (ngo_id, title, description, location, start_datetime, end_datetime, status, created_by_staff_id)
       VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
      [ctx.ngo_id, title, description || null, location || null, start_datetime, end_datetime || null, ctx.staff_id]
    );

    return res.status(201).json({ message: 'Event submitted for approval', id: r.insertId });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.get('/api/staff/events', requireAuth, requireRole('staff'), async (req, res) => {
  try {
    const ctx = await getStaffContext(req.user.user_id);
    if (!ctx) return res.status(404).json({ message: 'Staff record not found (assign NGO first).' });

    const [rows] = await pool.query(
      `SELECT event_id AS id, title, description, location, start_datetime, end_datetime, status
       FROM Event
       WHERE ngo_id=?
       ORDER BY created_at DESC`,
      [ctx.ngo_id]
    );
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Staff creates a cause (pending)
app.post('/api/staff/causes', requireAuth, requireRole('staff'), async (req, res) => {
  const { title, description, goal_amount, category, start_date, end_date } = req.body;
  try {
    const ctx = await getStaffContext(req.user.user_id);
    if (!ctx) return res.status(404).json({ message: 'Staff record not found (assign NGO first).' });
    if (!title || !goal_amount) return res.status(400).json({ message: 'title and goal_amount required' });

    const [r] = await pool.query(
      `INSERT INTO Cause (ngo_id, title, description, goal_amount, category, start_date, end_date, status, created_by_staff_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
      [ctx.ngo_id, title, description || null, goal_amount, category || null, start_date || null, end_date || null, ctx.staff_id]
    );

    return res.status(201).json({ message: 'Cause submitted for approval', id: r.insertId });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.get('/api/staff/causes', requireAuth, requireRole('staff'), async (req, res) => {
  try {
    const ctx = await getStaffContext(req.user.user_id);
    if (!ctx) return res.status(404).json({ message: 'Staff record not found (assign NGO first).' });

    const [rows] = await pool.query(
      `SELECT cause_id AS id, title, description, goal_amount, category, start_date, end_date, status
       FROM Cause
       WHERE ngo_id=?
       ORDER BY cause_id DESC`,
      [ctx.ngo_id]
    );
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// ---------- ADMIN ----------

// Admin: list causes (optionally filter by status)
//   GET /api/admin/causes                -> all
//   GET /api/admin/causes?status=pending -> pending only
app.get('/api/admin/causes', requireAuth, requireRole('admin'), async (req, res) => {
  const status = (req.query.status || '').toString().trim().toLowerCase();
  const allowed = ['pending', 'approved', 'rejected'];
  const where = allowed.includes(status) ? 'WHERE c.status = ?' : '';
  const params = allowed.includes(status) ? [status] : [];
  try {
    const [rows] = await pool.query(
      `
      SELECT
        c.cause_id AS id,
        c.ngo_id,
        n.name AS ngo_name,
        c.title,
        c.description,
        c.goal_amount,
        c.category,
        c.start_date,
        c.end_date,
        c.status
      FROM Cause c
      JOIN NGO n ON n.ngo_id = c.ngo_id
      ${where}
      ORDER BY c.cause_id DESC
      LIMIT 1000
      `,
      params
    );
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Admin: list events (optionally filter by status)
//   GET /api/admin/events                -> all
//   GET /api/admin/events?status=pending -> pending only
app.get('/api/admin/events', requireAuth, requireRole('admin'), async (req, res) => {
  const status = (req.query.status || '').toString().trim().toLowerCase();
  const allowed = ['pending', 'approved', 'rejected'];
  const where = allowed.includes(status) ? 'WHERE e.status = ?' : '';
  const params = allowed.includes(status) ? [status] : [];
  try {
    const [rows] = await pool.query(
      `
      SELECT
        e.event_id AS id,
        e.ngo_id,
        n.name AS ngo_name,
        e.title,
        e.description,
        e.location,
        e.start_datetime,
        e.end_datetime,
        e.status
      FROM Event e
      JOIN NGO n ON n.ngo_id = e.ngo_id
      ${where}
      ORDER BY e.created_at DESC
      LIMIT 1000
      `,
      params
    );
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Manage causes (direct create/update/delete) - kept for compatibility with existing admin form
app.post('/api/admin/causes', requireAuth, requireRole('admin'), async (req, res) => {
  const { ngo_id, title, goal_amount, category, start_date, end_date, description } = req.body;
  try {
    const [r] = await pool.query(
      `INSERT INTO Cause (ngo_id, title, description, goal_amount, category, start_date, end_date, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'approved')`,
      [ngo_id, title, description, goal_amount, category || null, start_date || null, end_date || null]
    );

    await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
      req.user.user_id,
      `Created cause #${r.insertId}: ${title}`,
    ]);

    return res.status(201).json({ message: 'Cause created', id: r.insertId });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.put('/api/admin/causes/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const { ngo_id, title, goal_amount, category, start_date, end_date, description, status } = req.body;

  try {
    await pool.query(
      `UPDATE Cause
       SET ngo_id=?, title=?, description=?, goal_amount=?, category=?, start_date=?, end_date=?, status=COALESCE(?, status)
       WHERE cause_id=?`,
      [ngo_id, title, description, goal_amount, category || null, start_date || null, end_date || null, status || null, id]
    );

    await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
      req.user.user_id,
      `Updated cause #${id}: ${title}`,
    ]);

    return res.json({ message: 'Cause updated' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Approval endpoint for pending causes
app.patch('/api/admin/causes/:id/status', requireAuth, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body;
  const allowed = ['pending', 'approved', 'rejected'];
  if (!allowed.includes(String(status || '').toLowerCase())) {
    return res.status(400).json({ message: 'Invalid status' });
  }
  try {
    await pool.query('UPDATE Cause SET status=? WHERE cause_id=?', [status.toLowerCase(), id]);
    await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
      req.user.user_id,
      `Set cause #${id} status -> ${status}`,
    ]);
    return res.json({ message: 'Status updated' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.delete('/api/admin/causes/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  try {
    await pool.query('DELETE FROM Cause WHERE cause_id = ?', [id]);

    await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
      req.user.user_id,
      `Deleted cause #${id}`,
    ]);

    return res.json({ message: 'Deleted' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Admin: list donations (used by admin/donations.html)
app.get('/api/admin/donations', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const search = (req.query.search || '').toString().trim();
    const like = `%${search}%`;

    const [rows] = await pool.query(
      `
      SELECT
        d.donation_id,
        d.amount,
        d.donation_date,
        u.name AS donor_name,
        u.email AS donor_email,
        c.title AS cause_title
      FROM Donation d
      JOIN Users u ON u.user_id = d.user_id
      LEFT JOIN Donation_Cause dc ON dc.donation_id = d.donation_id
      LEFT JOIN Cause c ON c.cause_id = dc.cause_id
      ${search ? 'WHERE u.email LIKE ? OR u.name LIKE ? OR c.title LIKE ?' : ''}
      ORDER BY d.donation_date DESC
      LIMIT 300
      `,
      search ? [like, like, like] : []
    );

    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.put('/api/admin/donations/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const { amount } = req.body;

  try {
    await pool.query('UPDATE Donation SET amount=? WHERE donation_id=?', [Number(amount), id]);
    await pool.query('UPDATE Donation_Cause SET amount_allocated=? WHERE donation_id=?', [
      Number(amount),
      id,
    ]);

    await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
      req.user.user_id,
      `Updated donation #${id} amount -> ${amount}`,
    ]);

    return res.json({ message: 'Donation updated' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.delete('/api/admin/donations/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);

  try {
    await pool.query('DELETE FROM Donation_Cause WHERE donation_id=?', [id]);
    await pool.query('DELETE FROM Donation WHERE donation_id=?', [id]);

    await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
      req.user.user_id,
      `Deleted donation #${id}`,
    ]);

    return res.json({ message: 'Donation deleted' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Approval endpoints for events
app.patch('/api/admin/events/:id/status', requireAuth, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body;
  const allowed = ['pending', 'approved', 'rejected'];
  if (!allowed.includes(String(status || '').toLowerCase())) {
    return res.status(400).json({ message: 'Invalid status' });
  }
  try {
    await pool.query('UPDATE Event SET status=? WHERE event_id=?', [status.toLowerCase(), id]);
    await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
      req.user.user_id,
      `Set event #${id} status -> ${status}`,
    ]);
    return res.json({ message: 'Status updated' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});
app.post('/api/staff/join-ngo', requireAuth, requireRole('staff'), async (req, res) => {
  try {
    const { ngo_id } = req.body;
    if (!ngo_id) return res.status(400).json({ message: 'ngo_id required' });

    const [[ngo]] = await pool.query('SELECT ngo_id, name FROM NGO WHERE ngo_id=? LIMIT 1', [Number(ngo_id)]);
    if (!ngo) return res.status(404).json({ message: 'NGO not found' });

    // upsert staff row (1 staff -> 1 NGO)
    const [[existing]] = await pool.query('SELECT staff_id FROM Staff WHERE user_id=? LIMIT 1', [req.user.user_id]);
    if (existing) {
      await pool.query('UPDATE Staff SET ngo_id=? WHERE user_id=?', [Number(ngo_id), req.user.user_id]);
    } else {
      await pool.query('INSERT INTO Staff (user_id, ngo_id) VALUES (?, ?)', [req.user.user_id, Number(ngo_id)]);
    }

    return res.json({ message: 'Assigned to NGO', ngo });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// Reports
app.get('/api/stats', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const [[stats]] = await pool.query(`
      SELECT
        COALESCE(SUM(amount), 0) AS totalFundsRaised,
        (SELECT COUNT(*) FROM Volunteer) AS activevolunteers,
        COALESCE(MAX(amount), 0) AS highestDonation
      FROM Donation
    `);
    return res.json(stats);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.get('/api/audit', requireAuth, requireRole('admin'), async (req, res) => {
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
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});
// ---------- ADMIN OPS (COMBINED) ----------
app.get('/api/admin/ops', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const type = String(req.query.type || '').toLowerCase();
    const ngo_id = req.query.ngo_id ? Number(req.query.ngo_id) : null;
    const q = String(req.query.q || '').trim();
    const minRating = req.query.minRating ? Number(req.query.minRating) : null;

    if (!type) return res.status(400).json({ message: 'type is required' });

    // ---- FEEDBACK LIST ----
    if (type === 'feedback') {
      const where = [];
      const params = [];

      if (ngo_id) { where.push('f.ngo_id = ?'); params.push(ngo_id); }
      if (minRating && !Number.isNaN(minRating)) { where.push('f.rating >= ?'); params.push(minRating); }

      if (q) {
        where.push('(u.name LIKE ? OR u.email LIKE ? OR f.message LIKE ? OR n.name LIKE ?)');
        const like = `%${q}%`;
        params.push(like, like, like, like);
      }

      const sql = `
        SELECT
          f.feedback_id,
          f.rating,
          f.message,
          f.timestamp,
          n.ngo_id,
          n.name AS ngo_name,
          u.user_id,
          u.name AS user_name,
          u.email AS user_email
        FROM Feedback f
        JOIN Users u ON u.user_id = f.user_id
        JOIN NGO n ON n.ngo_id = f.ngo_id
        ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
        ORDER BY f.timestamp DESC
        LIMIT 500
      `;

      const [rows] = await pool.query(sql, params);
      return res.json({ items: rows });
    }

    // ---- VOLUNTEERS LIST ----
    if (type === 'volunteers') {
      const where = [];
      const params = [];

      if (ngo_id) { where.push('v.primary_ngo_id = ?'); params.push(ngo_id); }

      if (q) {
        where.push('(u.name LIKE ? OR u.email LIKE ? OR v.skill LIKE ? OR v.availability LIKE ?)');
        const like = `%${q}%`;
        params.push(like, like, like, like);
      }

      const sql = `
        SELECT
          v.volunteer_id,
          v.skill,
          v.availability,
          v.primary_ngo_id,
          u.user_id,
          u.name AS user_name,
          u.email AS user_email
        FROM Volunteer v
        JOIN Users u ON u.user_id = v.user_id
        ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
        ORDER BY v.volunteer_id DESC
        LIMIT 500
      `;

      const [rows] = await pool.query(sql, params);
      return res.json({ items: rows });
    }

    return res.status(400).json({ message: 'Invalid type' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

app.patch('/api/admin/ops', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const type = String(req.body.type || '').toLowerCase();

    if (type === 'volunteer_primary_ngo') {
      const volunteer_id = Number(req.body.volunteer_id);
      const primary_ngo_id = (req.body.primary_ngo_id === null || req.body.primary_ngo_id === '' || typeof req.body.primary_ngo_id === 'undefined')
        ? null
        : Number(req.body.primary_ngo_id);

      if (!volunteer_id) return res.status(400).json({ message: 'volunteer_id required' });

      // optional: validate NGO exists if provided
      if (primary_ngo_id) {
        const [[ngo]] = await pool.query('SELECT ngo_id FROM NGO WHERE ngo_id=? LIMIT 1', [primary_ngo_id]);
        if (!ngo) return res.status(404).json({ message: 'NGO not found' });
      }

      await pool.query('UPDATE Volunteer SET primary_ngo_id=? WHERE volunteer_id=?', [primary_ngo_id, volunteer_id]);

      await pool.query('INSERT INTO Audit_Log (admin_id, action) VALUES (?, ?)', [
        req.user.user_id,
        `Set volunteer #${volunteer_id} primary_ngo_id -> ${primary_ngo_id === null ? 'NULL' : primary_ngo_id}`
      ]);

      return res.json({ message: 'Volunteer updated' });
    }

    return res.status(400).json({ message: 'Invalid type' });
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});


app.get('/api/category_breakdown', requireAuth, requireRole('admin'), async (req, res) => {
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
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ message: 'DB error', error: e.message });
  }
});

// ---------- frontend routes ----------
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'home.html')));

// receipt placeholder
app.get('/receipts/:id', (req, res) => {
  return res.send(`<h2>Receipt #${req.params.id}</h2><p>Build PDF/HTML receipt here.</p>`);
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.use((req, res) => res.status(404).json({ message: 'Not found' }));

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
