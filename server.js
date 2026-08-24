"use strict";

var express = require("express");
var cookieParser = require("cookie-parser");
var crypto = require("crypto");
var path = require("path");
var { Pool } = require("pg");

var PORT = process.env.PORT || 3000;
var APP_PASSWORD = process.env.APP_PASSWORD;
var SESSION_SECRET = process.env.SESSION_SECRET;
var IS_PROD = process.env.NODE_ENV === "production";

if (!APP_PASSWORD || !SESSION_SECRET) {
  console.error("Missing required env vars: APP_PASSWORD and SESSION_SECRET must both be set.");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("Missing required env var: DATABASE_URL.");
  process.exit(1);
}

var pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/**
 * A stateless auth cookie: its value is just an HMAC of the password and
 * secret, so any server instance can validate it without a session store
 * (and it survives a dyno restart). There's nothing per-user to revoke —
 * fine for a single-password personal tool. Rotate SESSION_SECRET or
 * APP_PASSWORD to invalidate every outstanding cookie at once.
 */
function authToken() {
  return crypto.createHmac("sha256", SESSION_SECRET).update(APP_PASSWORD).digest("hex");
}

var COOKIE_NAME = "fn_auth";
var COOKIE_OPTS = {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: "lax",
  maxAge: 1000 * 60 * 60 * 24 * 90 // 90 days
};

function isValidToken(token) {
  if (!token) return false;
  var expected = Buffer.from(authToken());
  var actual = Buffer.from(String(token));
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function requireAuth(req, res, next) {
  var token = req.cookies && req.cookies[COOKIE_NAME];
  if (isValidToken(token)) {
    return next();
  }
  if (req.path.indexOf("/api/") === 0) {
    return res.status(401).json({ error: "unauthorized" });
  }
  return res.redirect("/login");
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
  ).then(function () {
    return pool.query("INSERT INTO app_state (id, data) VALUES (1, '{}'::jsonb) ON CONFLICT (id) DO NOTHING");
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
  if (isValidToken(token)) {
    return res.redirect("/");
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/api/login", function (req, res) {
  var password = (req.body && req.body.password) || "";
  if (password && password === APP_PASSWORD) {
    res.cookie(COOKIE_NAME, authToken(), COOKIE_OPTS);
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, error: "Incorrect password" });
});

app.post("/api/logout", function (req, res) {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
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
