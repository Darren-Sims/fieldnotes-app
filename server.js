"use strict";

var express = require("express");
var cookieParser = require("cookie-parser");
var crypto = require("crypto");
var path = require("path");
var { Pool } = require("pg");

var PORT = process.env.PORT || 3000;
var APP_PASSWORD = process.env.APP_PASSWORD;
var SESSION_SECRET = process.env.SESSION_SECRET;
var RECOVERY_CODE = process.env.RECOVERY_CODE || "";
var IS_PROD = process.env.NODE_ENV === "production";

if (!APP_PASSWORD || !SESSION_SECRET) {
  console.error("Missing required env vars: APP_PASSWORD and SESSION_SECRET must both be set.");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("Missing required env var: DATABASE_URL.");
  process.exit(1);
}
if (!RECOVERY_CODE) {
  console.warn("RECOVERY_CODE is not set — the Forgot Password flow will refuse to run until it is.");
}

var pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ====================== PASSWORD STORAGE ====================== */
/* The login password lives in the database (salted + hashed with scrypt),
   not just as a static env var — that's what makes an actual "forgot
   password" flow possible. APP_PASSWORD is only ever used once, to seed
   the very first row the first time this app boots against a fresh
   database. After that the database is the source of truth; changing
   APP_PASSWORD on Render will NOT change the login password — use the
   Forgot Password flow (or a direct DB update) instead. */

function hashPassword(password) {
  var salt = crypto.randomBytes(16);
  var derived = crypto.scryptSync(password, salt, 64);
  return salt.toString("hex") + ":" + derived.toString("hex");
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  var parts = stored.split(":");
  if (parts.length !== 2) return false;
  var salt = Buffer.from(parts[0], "hex");
  var expected = Buffer.from(parts[1], "hex");
  var actual = crypto.scryptSync(password, salt, expected.length);
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function getCurrentPasswordHash() {
  return pool.query("SELECT password_hash FROM app_auth WHERE id = 1").then(function (result) {
    return result.rows[0] ? result.rows[0].password_hash : null;
  });
}

/* ====================== SESSION COOKIE ====================== */
/* A stateless auth cookie: its value is an HMAC of the current password
   hash, so any server instance can validate it without a session store
   (and it survives a dyno restart). It also means resetting the password
   automatically invalidates every outstanding cookie — anyone (including
   you, elsewhere) gets signed out and has to log in with the new one. */

function signToken(passwordHash) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(passwordHash).digest("hex");
}

function isValidToken(token, passwordHash) {
  if (!token || !passwordHash) return false;
  var expected = Buffer.from(signToken(passwordHash));
  var actual = Buffer.from(String(token));
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

var COOKIE_NAME = "fn_auth";
var COOKIE_OPTS = {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: "lax",
  maxAge: 1000 * 60 * 60 * 24 * 90 // 90 days
};

function unauthenticated(req, res) {
  if (req.path.indexOf("/api/") === 0) {
    return res.status(401).json({ error: "unauthorized" });
  }
  return res.redirect("/login");
}

function requireAuth(req, res, next) {
  var token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return unauthenticated(req, res);
  getCurrentPasswordHash()
    .then(function (hash) {
      if (isValidToken(token, hash)) return next();
      return unauthenticated(req, res);
    })
    .catch(function (err) {
      console.error("Auth check failed:", err);
      return unauthenticated(req, res);
    });
}

/* ====================== PASSWORD RESET RATE LIMIT ====================== */
/* Simple in-memory throttle — resets on restart, which is fine for a
   single-instance personal tool. Just enough to blunt naive guessing of
   the recovery code; the code itself (long + random) is the real defense. */

var resetAttempts = {};
function isRateLimited(key) {
  var now = Date.now();
  var rec = resetAttempts[key];
  if (!rec || now - rec.windowStart > 15 * 60 * 1000) {
    resetAttempts[key] = { count: 1, windowStart: now };
    return false;
  }
  rec.count++;
  return rec.count > 10;
}

/* ====================== DB SETUP ====================== */

function ensureSchema() {
  return pool.query(
    "CREATE TABLE IF NOT EXISTS app_state (" +
      "id INTEGER PRIMARY KEY DEFAULT 1, " +
      "data JSONB NOT NULL DEFAULT '{}'::jsonb, " +
      "updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), " +
      "CONSTRAINT single_row CHECK (id = 1)" +
    ")"
  )
    .then(function () {
      return pool.query("INSERT INTO app_state (id, data) VALUES (1, '{}'::jsonb) ON CONFLICT (id) DO NOTHING");
    })
    .then(function () {
      return pool.query(
        "CREATE TABLE IF NOT EXISTS app_auth (" +
          "id INTEGER PRIMARY KEY DEFAULT 1, " +
          "password_hash TEXT NOT NULL, " +
          "updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), " +
          "CONSTRAINT single_row CHECK (id = 1)" +
        ")"
      );
    })
    .then(function () {
      // Only ever seeds the row the first time — after this, APP_PASSWORD
      // the env var is never read again.
      return pool.query(
        "INSERT INTO app_auth (id, password_hash) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
        [hashPassword(APP_PASSWORD)]
      );
    });
}

/* ====================== APP ====================== */

var app = express();
app.disable("x-powered-by");
app.use(cookieParser());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: false }));

app.get("/healthz", function (req, res) { res.status(200).send("ok"); });

app.get("/login", function (req, res) {
  var token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return res.sendFile(path.join(__dirname, "public", "login.html"));
  getCurrentPasswordHash()
    .then(function (hash) {
      if (isValidToken(token, hash)) return res.redirect("/");
      res.sendFile(path.join(__dirname, "public", "login.html"));
    })
    .catch(function () {
      res.sendFile(path.join(__dirname, "public", "login.html"));
    });
});

app.post("/api/login", function (req, res) {
  var password = (req.body && req.body.password) || "";
  if (!password) return res.status(401).json({ ok: false, error: "Incorrect password" });
  getCurrentPasswordHash()
    .then(function (hash) {
      if (hash && verifyPassword(password, hash)) {
        res.cookie(COOKIE_NAME, signToken(hash), COOKIE_OPTS);
        return res.json({ ok: true });
      }
      return res.status(401).json({ ok: false, error: "Incorrect password" });
    })
    .catch(function (err) {
      console.error("POST /api/login failed:", err);
      res.status(500).json({ ok: false, error: "Something went wrong — try again" });
    });
});

app.post("/api/logout", function (req, res) {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/forgot-password", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "forgot-password.html"));
});

app.post("/api/reset-password", function (req, res) {
  var key = req.ip || "unknown";
  if (isRateLimited(key)) {
    return res.status(429).json({ ok: false, error: "Too many attempts — wait a while and try again" });
  }
  if (!RECOVERY_CODE) {
    return res.status(503).json({ ok: false, error: "Password recovery isn't set up yet" });
  }
  var recoveryCode = (req.body && req.body.recoveryCode) || "";
  var newPassword = (req.body && req.body.newPassword) || "";
  if (!recoveryCode || !newPassword) {
    return res.status(400).json({ ok: false, error: "Enter the recovery code and a new password" });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ ok: false, error: "New password must be at least 8 characters" });
  }
  var expected = Buffer.from(RECOVERY_CODE);
  var actual = Buffer.from(recoveryCode);
  var validCode = actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  if (!validCode) {
    return res.status(401).json({ ok: false, error: "Incorrect recovery code" });
  }
  var newHash = hashPassword(newPassword);
  pool.query(
    "INSERT INTO app_auth (id, password_hash, updated_at) VALUES (1, $1, now()) " +
      "ON CONFLICT (id) DO UPDATE SET password_hash = $1, updated_at = now()",
    [newHash]
  )
    .then(function () {
      res.json({ ok: true });
    })
    .catch(function (err) {
      console.error("POST /api/reset-password failed:", err);
      res.status(500).json({ ok: false, error: "Could not reset the password — try again" });
    });
});

app.use(requireAuth);

app.get("/", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api/state", function (req, res) {
  pool.query("SELECT data FROM app_state WHERE id = 1")
    .then(function (result) {
      res.json(result.rows[0] ? result.rows[0].data : {});
    })
    .catch(function (err) {
      console.error("GET /api/state failed:", err);
      res.status(500).json({ error: "Could not load data" });
    });
});

app.put("/api/state", function (req, res) {
  var data = req.body;
  pool.query(
    "INSERT INTO app_state (id, data, updated_at) VALUES (1, $1, now()) " +
      "ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()",
    [data]
  )
    .then(function () { res.json({ ok: true }); })
    .catch(function (err) {
      console.error("PUT /api/state failed:", err);
      res.status(500).json({ error: "Could not save data" });
    });
});

ensureSchema()
  .then(function () {
    app.listen(PORT, function () {
      console.log("Fieldnotes listening on port " + PORT);
    });
  })
  .catch(function (err) {
    console.error("Failed to set up database schema:", err);
    process.exit(1);
  });
