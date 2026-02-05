// index.js (FULL UPDATED + FIXED)
// ✅ JWT Auth (Register/Login/Profile)
// ✅ Secure Blog CRUD (owner-only update/delete)
// ✅ Fixed SQL placeholder bug
// ✅ Uses dotenv for secrets
// ✅ Better CORS + validation
// ✅ No body-parser needed (Express has it)

require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();

// --------- Middlewares ----------
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
    credentials: true,
  }),
);
app.use(cookieParser());

// --------- PostgreSQL ----------
const pool = new Pool({
  user: process.env.PG_USER || "root",
  host: process.env.PG_HOST || "localhost",
  database: process.env.PG_DATABASE || "ecommarce",
  password: process.env.PG_PASSWORD || "root",
  port: Number(process.env.PG_PORT || 5432),
});

// --------- JWT Configs ----------
const JWT_SECRET = process.env.JWT_SECRET || "change_me_in_env";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "15m";

const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || "refresh_secret_change_me";
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";

// --------- Helpers ----------
const signAccessToken = (payload) =>
  jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

const signRefreshToken = (payload) =>
  jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });

const isProd = process.env.NODE_ENV === "production";
const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? "none" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: "/",
};

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// --------- Root ----------
app.get("/", (req, res) => res.send("Server is running ✅"));

// =======================================
// 🔐 AUTH ROUTES
// =======================================

// ✅ Register
app.post("/register", async (req, res) => {
  try {
    const { first_name, last_name, email, password, phone } = req.body;

    if (!first_name || !last_name || !email || !password) {
      return res.status(400).json({ message: "All fields are required!" });
    }

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email=$1",
      [email],
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (first_name, last_name, email, password, phone)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, first_name, last_name, email, phone, role, created_at`,
      [first_name, last_name, email, hashedPassword, phone || null],
    );

    return res.status(201).json({
      message: "User registered successfully",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE email=$1", [
      email,
    ]);

    if (userRes.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const user = userRes.rows[0];

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const payload = { id: user.id, email: user.email, role: user.role };

    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    // store refresh token in cookie
    res.cookie("jwt", refreshToken, cookieOptions);

    return res.json({
      message: "Login successful",
      accessToken, // ✅ frontend expects this name
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        first_name: user.first_name,
        last_name: user.last_name,
        phone: user.phone,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Refresh
app.get("/refresh", (req, res) => {
  const refreshToken = req.cookies?.jwt;
  if (!refreshToken)
    return res.status(401).json({ message: "No refresh token" });

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const accessToken = signAccessToken({
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
    });

    return res.json({ accessToken });
  } catch (err) {
    return res.status(401).json({ message: "Refresh token invalid" });
  }
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("jwt", cookieOptions);
  return res.json({ message: "Logged out" });
});

// ✅ Profile (Protected)
app.get("/profile", authenticate, async (req, res) => {
  try {
    const userRes = await pool.query(
      `SELECT id, first_name, last_name, email, phone, role, created_at, updated_at
       FROM users
       WHERE id=$1`,
      [req.user.id],
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json(userRes.rows[0]);
  } catch (err) {
    console.error("Profile error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ Update Profile (Protected)
app.put("/profile", authenticate, async (req, res) => {
  try {
    const { first_name, last_name, email, phone } = req.body;

    // Optional: basic validation
    if (!first_name || !last_name || !email) {
      return res
        .status(400)
        .json({ message: "first_name, last_name, email required" });
    }

    // Prevent duplicate email for other users
    const emailCheck = await pool.query(
      "SELECT id FROM users WHERE email=$1 AND id<>$2",
      [email, req.user.id],
    );
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ message: "Email already in use" });
    }

    const updated = await pool.query(
      `UPDATE users
       SET first_name=$1,
           last_name=$2,
           email=$3,
           phone=$4,
           updated_at=NOW()
       WHERE id=$5
       RETURNING id, first_name, last_name, email, phone, role, updated_at`,
      [first_name, last_name, email, phone || null, req.user.id],
    );

    return res.json({
      message: "Profile updated successfully",
      user: updated.rows[0],
    });
  } catch (err) {
    console.error("Update profile error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// =======================================
// 📝 BLOG ROUTES (CRUD)
// =======================================

// ✅ CREATE Blog (Protected)
app.post("/blogs", authenticate, async (req, res) => {
  try {
    const { title, description } = req.body;

    if (!title || !description) {
      return res
        .status(400)
        .json({ message: "Title and description are required" });
    }

    const result = await pool.query(
      `INSERT INTO blogs (title, description, user_id)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [title, description, req.user.id],
    );

    return res
      .status(201)
      .json({ message: "Blog created", blog: result.rows[0] });
  } catch (err) {
    console.error("Create blog error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ GET All Blogs (Public)
app.get("/blogs", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*, u.first_name, u.last_name
       FROM blogs b
       JOIN users u ON u.id = b.user_id
       ORDER BY b.created_at DESC`,
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Fetch blogs error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ GET My Blogs (Protected)
app.get("/get_my_blogs", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*, u.first_name, u.last_name, u.email
       FROM blogs b
       INNER JOIN users u ON b.user_id = u.id
       WHERE b.user_id = $1
       ORDER BY b.created_at DESC`,
      [req.user.id],
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Fetch my blogs error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ GET Single Blog (Public)
app.get("/blogs/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*, u.first_name, u.last_name
       FROM blogs b
       JOIN users u ON u.id = b.user_id
       WHERE b.id=$1`,
      [req.params.id],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Blog not found" });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Fetch blog error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ UPDATE Blog (Protected + Owner Only)  ✅ FIXED
app.put("/blogs/:id", authenticate, async (req, res) => {
  try {
    const { title, description } = req.body;

    if (!title || !description) {
      return res
        .status(400)
        .json({ message: "Title and description are required" });
    }

    const result = await pool.query(
      `UPDATE blogs
       SET title=$1, description=$2, updated_at=NOW()
       WHERE id=$3 AND user_id=$4
       RETURNING *`,
      [title, description, req.params.id, req.user.id],
    );

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ message: "Blog not found or unauthorized" });
    }

    return res.json({ message: "Blog updated", blog: result.rows[0] });
  } catch (err) {
    console.error("Update blog error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ DELETE Blog (Protected + Owner Only) ✅ FIXED
app.delete("/blogs/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM blogs WHERE id=$1 AND user_id=$2`,
      [req.params.id, req.user.id],
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ message: "Blog not found or unauthorized" });
    }

    return res.status(200).json({ message: "Blog deleted successfully" });
  } catch (err) {
    console.error("Delete blog error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// =======================================
// 🚀 START SERVER
// =======================================
const PORT = Number(process.env.PORT || 5001);
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
