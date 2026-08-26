"use strict";

var express = require("express");
var cookieParser = require("cookie-parser");
var crypto = require("crypto");
var path = require("path");
var multer = require("multer");
var PDFDocument = require("pdfkit");
var { Pool } = require("pg");

var MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024; // 10MB
var upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_ATTACHMENT_BYTES }
});

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
    })
    .then(function () {
      // Uploaded file attachments live in their own table rather than in the
      // app_state JSON blob — that blob is rewritten in full on every
      // autosave, so putting file bytes in it would mean re-sending every
      // attached file's bytes on every unrelated edit. Attachments are
      // fetched per-project on demand instead, and only referenced by id
      // from the frontend's in-memory state (nothing in app_state points at
      // them directly — the project id they're linked to is enough).
      return pool.query(
        "CREATE TABLE IF NOT EXISTS attachments (" +
          "id TEXT PRIMARY KEY, " +
          "project_id TEXT NOT NULL, " +
          "label TEXT NOT NULL, " +
          "filename TEXT NOT NULL, " +
          "mime_type TEXT NOT NULL, " +
          "size_bytes INTEGER NOT NULL, " +
          "file_data BYTEA NOT NULL, " +
          "created_at TIMESTAMPTZ NOT NULL DEFAULT now()" +
        ")"
      );
    })
    .then(function () {
      return pool.query("CREATE INDEX IF NOT EXISTS attachments_project_id_idx ON attachments (project_id)");
    })
    .then(function () {
      // A public, unauthenticated snapshot of one contract's fields,
      // addressed by an unguessable token — kept separate from app_state
      // (which requires login) so a client holding just the link can view,
      // and download a PDF of, their contract without a Fieldnotes account.
      // One row per contract (contract_id is unique) so re-sharing after an
      // edit just refreshes the same row/token rather than minting a new one.
      return pool.query(
        "CREATE TABLE IF NOT EXISTS contract_shares (" +
          "token TEXT PRIMARY KEY, " +
          "contract_id TEXT NOT NULL UNIQUE, " +
          "data JSONB NOT NULL, " +
          "created_at TIMESTAMPTZ NOT NULL DEFAULT now(), " +
          "updated_at TIMESTAMPTZ NOT NULL DEFAULT now()" +
        ")"
      );
    })
    .then(function () {
      // Social content posts (the client content-approval pipeline) live in
      // their own table rather than the app_state blob, same reasoning as
      // attachments — but more importantly, a client approving or requesting
      // changes on a post via a public share link writes directly to a
      // single row here. If posts instead lived inside app_state (which is
      // always rewritten as one full JSON document on every autosave), a
      // client's approval and an in-app edit landing around the same time
      // could silently clobber one another. Per-row updates avoid that.
      return pool.query(
        "CREATE TABLE IF NOT EXISTS content_posts (" +
          "id TEXT PRIMARY KEY, " +
          "project_id TEXT NOT NULL, " +
          "platform TEXT NOT NULL DEFAULT '', " +
          "stage TEXT NOT NULL DEFAULT 'idea', " +
          "copy_text TEXT NOT NULL DEFAULT '', " +
          "notes TEXT NOT NULL DEFAULT '', " +
          "scheduled_date TEXT NOT NULL DEFAULT '', " +
          "client_feedback TEXT NOT NULL DEFAULT '', " +
          "posted_at TIMESTAMPTZ, " +
          "created_at TIMESTAMPTZ NOT NULL DEFAULT now(), " +
          "updated_at TIMESTAMPTZ NOT NULL DEFAULT now()" +
        ")"
      );
    })
    .then(function () {
      return pool.query("CREATE INDEX IF NOT EXISTS content_posts_project_id_idx ON content_posts (project_id)");
    })
    .then(function () {
      // A public, unauthenticated link onto one project's content queue —
      // same unguessable-token pattern as contract_shares. Unlike contract
      // shares this holds no data snapshot: content_posts is already the
      // live source of truth, so the public page just queries it directly
      // by project_id at request time. One row per project.
      return pool.query(
        "CREATE TABLE IF NOT EXISTS content_shares (" +
          "token TEXT PRIMARY KEY, " +
          "project_id TEXT NOT NULL UNIQUE, " +
          "created_at TIMESTAMPTZ NOT NULL DEFAULT now()" +
        ")"
      );
    })
    .then(function () {
      // Signatures live in their own table for the same reason content_posts
      // does: contract_shares.data is a full-document snapshot that gets
      // overwritten wholesale every time the contract is edited in-app
      // (scheduleShareSync), so a client's signature landing inside that
      // JSONB blob would risk getting silently wiped out by Darren's next
      // keystroke. A dedicated row per (contract, role) survives that. One
      // contract can have at most one developer signature and one client
      // signature — signing again just replaces the row.
      return pool.query(
        "CREATE TABLE IF NOT EXISTS contract_signatures (" +
          "contract_id TEXT NOT NULL, " +
          "role TEXT NOT NULL, " +
          "name TEXT NOT NULL DEFAULT '', " +
          "image_data TEXT NOT NULL, " +
          "signed_at TIMESTAMPTZ NOT NULL DEFAULT now(), " +
          "PRIMARY KEY (contract_id, role)" +
        ")"
      );
    });
}

/* Documents Office can preview inline in a browser tab; everything else
   (docx, xlsx, zip, ...) downloads instead, since browsers can't render it. */
var INLINE_MIME_TYPES = {
  "application/pdf": true,
  "image/png": true,
  "image/jpeg": true,
  "image/gif": true,
  "image/webp": true,
  "image/svg+xml": true,
  "text/plain": true
};

/* ====================== CONTRACT PDF RENDERING ====================== */
/* Shared by the authenticated "Download .pdf" button and the public share
   link's PDF download — both just hand this the same plain-fields object
   the frontend already renders a preview from (see contractSharePayload
   in index.html), so the PDF, the on-screen preview and the .md export
   all stay in sync with a single source of truth for wording/order. */

function fmtDatePdf(iso) {
  if (!iso) return "";
  var d = new Date(iso + "T00:00:00");
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

function moneyPdf(n) {
  var v = Number(n);
  if (n === "" || n === null || n === undefined || isNaN(v)) return "";
  return "£" + v.toLocaleString("en-GB", { maximumFractionDigits: 0 });
}

function contractPdfFilename(data) {
  var base = (data && data.projectName) ? data.projectName : "contract";
  return String(base).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "contract";
}

var HEX_COLOR_RE = /^#[0-9a-f]{6}$/i;
function validAccentColor(value) {
  return typeof value === "string" && HEX_COLOR_RE.test(value) ? value : null;
}

var MAX_SIGNATURE_DATA_URL_LENGTH = 2000000; // ~1.5MB image, generous for a drawn or uploaded signature
var SIGNATURE_DATA_URL_RE = /^data:image\/(png|jpeg|jpg);base64,/i;
function validSignatureImage(value) {
  return typeof value === "string" && value.length <= MAX_SIGNATURE_DATA_URL_LENGTH && SIGNATURE_DATA_URL_RE.test(value);
}

function getContractSignatures(contractId) {
  return pool.query(
    "SELECT role, name, image_data, signed_at FROM contract_signatures WHERE contract_id = $1",
    [contractId]
  ).then(function (result) {
    var out = { developer: null, client: null };
    result.rows.forEach(function (r) {
      out[r.role] = { name: r.name, imageData: r.image_data, signedAt: r.signed_at };
    });
    return out;
  });
}

function upsertContractSignature(contractId, role, name, imageData) {
  return pool.query(
    "INSERT INTO contract_signatures (contract_id, role, name, image_data, signed_at) VALUES ($1, $2, $3, $4, now()) " +
      "ON CONFLICT (contract_id, role) DO UPDATE SET name = EXCLUDED.name, image_data = EXCLUDED.image_data, signed_at = now() " +
      "RETURNING signed_at",
    [contractId, role, name || "", imageData]
  );
}

function renderContractPdf(res, data) {
  data = data || {};
  var filename = contractPdfFilename(data);
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", 'attachment; filename="' + filename + '.pdf"');

  var doc = new PDFDocument({ margin: 54, size: "A4" });
  doc.pipe(res);

  function h2(text) {
    doc.moveDown(0.9);
    doc.font("Helvetica-Bold").fontSize(10).fillColor("#555555").text(String(text).toUpperCase(), { characterSpacing: 0.4 });
    doc.moveDown(0.25);
  }
  function body(text) {
    doc.font("Helvetica").fontSize(10.5).fillColor("#111111").text(String(text || ""), { lineGap: 3 });
  }
  function bullet(text) {
    doc.font("Helvetica").fontSize(10.5).fillColor("#111111").text("•  " + text, { lineGap: 3, indent: 8 });
  }

  var today = new Date().toISOString().slice(0, 10);
  var deliverables = (data.deliverables || []).filter(function (d) { return d && String(d).trim(); });

  doc.font("Helvetica-Bold").fontSize(19).fillColor("#111111").text(data.projectName || "Project agreement");
  doc.moveDown(0.15);
  doc.font("Helvetica").fontSize(9.5).fillColor("#555555").text(
    "Between " + (data.yourName || "—") + " and " + (data.clientName || "—") +
    (data.clientCompany ? " (" + data.clientCompany + ")" : "") + " · " + fmtDatePdf(data.contractDate || today)
  );

  // A subtle accent bar in the connected client's brand colour, matching
  // the same treatment shown in the app and on the public share page.
  // Only drawn when the contract is linked to a project with a client that
  // has a colour set — otherwise the document stays plain.
  var accentColor = validAccentColor(data.clientAccent);
  if (accentColor) {
    doc.moveDown(0.5);
    doc.rect(doc.page.margins.left, doc.y, doc.page.width - doc.page.margins.left - doc.page.margins.right, 2.5).fill(accentColor);
    doc.moveDown(0.6);
  }

  h2("Parties");
  body(
    "This agreement is between " + (data.yourName || "the Developer") + ' ("the Developer")' +
    (data.yourAddress ? ", of " + data.yourAddress : "") + ", and " + (data.clientName || "the Client") +
    (data.clientCompany ? " of " + data.clientCompany : "") + ' ("the Client")' +
    (data.clientAddress ? ", of " + data.clientAddress : "") + "."
  );

  if (data.overview) { h2("Scope of work"); body(data.overview); }
  if (deliverables.length) {
    h2("Deliverables");
    deliverables.forEach(function (d) { bullet(d); });
  }
  if (data.exclusions) { h2("Not included"); body(data.exclusions); }
  if (data.startDate || data.timeline) {
    h2("Timeline");
    body(((data.startDate ? "Starting " + fmtDatePdf(data.startDate) + ". " : "") + (data.timeline || "")).trim());
  }
  if (data.price) {
    h2("Fees");
    body(moneyPdf(data.price) + (data.paymentTerms ? "\n" + data.paymentTerms : ""));
  }
  if (data.revisions) { h2("Revisions"); body(data.revisions); }
  if (data.ownership) { h2("Ownership & IP"); body(data.ownership); }
  if (data.cancellation) { h2("Cancellation"); body(data.cancellation); }
  if (data.liability) { h2("Liability"); body(data.liability); }
  if (data.confidentiality) { h2("Confidentiality"); body(data.confidentiality); }

  h2("Governing law");
  body("This agreement is governed by the law of " + (data.governingLaw || "England and Wales") + ".");

  h2("Agreed");
  doc.moveDown(0.3);
  var signatures = data.signatures || {};
  renderSignatureBlock("Client", data.clientName, signatures.client);
  doc.moveDown(0.6);
  renderSignatureBlock("Developer", data.yourName, signatures.developer);

  function renderSignatureBlock(roleLabel, personName, sig) {
    doc.font("Helvetica-Bold").fontSize(9.5).fillColor("#555555").text(roleLabel.toUpperCase(), { characterSpacing: 0.3 });
    doc.moveDown(0.2);
    if (sig && sig.imageData) {
      var m = /^data:image\/(png|jpeg|jpg);base64,(.+)$/i.exec(sig.imageData);
      if (m) {
        try {
          doc.image(Buffer.from(m[2], "base64"), { fit: [170, 56] });
          doc.moveDown(0.15);
        } catch (imgErr) {
          console.error("renderContractPdf: could not draw signature image:", imgErr);
        }
      }
      body((sig.name || personName || "") + " — signed " + fmtDatePdf(String(sig.signedAt).slice(0, 10)));
    } else {
      doc.font("Helvetica").fontSize(10).fillColor("#8a8a8a").text((personName || "") + " — not yet signed");
    }
  }

  doc.end();
}

/* ====================== APP ====================== */

var app = express();
app.disable("x-powered-by");
app.use(cookieParser());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: false }));

app.get("/healthz", function (req, res) { res.status(200).send("ok"); });

// The brand logo — used as the favicon and as the small mark shown on
// every page (login, reset, share links, the app itself). Public and
// unauthenticated on purpose: it needs to load on the logged-out pages.
app.get("/logo.png", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "logo.png"));
});
app.get("/logo-dark.png", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "logo-dark.png"));
});
app.get("/favicon.ico", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "logo.png"));
});

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

/* ====================== PUBLIC CONTRACT SHARE LINKS ====================== */
/* No auth on these three — the unguessable token IS the credential, same
   idea as the recovery code. A client with the link can view the contract
   and download a PDF of it without ever logging in to Fieldnotes. */

app.get("/share/contract/:token", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "share-contract.html"));
});

app.get("/api/public/contract-shares/:token", function (req, res) {
  pool.query("SELECT contract_id, data, updated_at FROM contract_shares WHERE token = $1", [req.params.token])
    .then(function (result) {
      var row = result.rows[0];
      if (!row) return res.status(404).json({ error: "not-found" });
      return getContractSignatures(row.contract_id).then(function (signatures) {
        res.json({ data: row.data, updatedAt: row.updated_at, signatures: signatures });
      });
    })
    .catch(function (err) {
      console.error("GET /api/public/contract-shares/:token failed:", err);
      res.status(500).json({ error: "Could not load this contract" });
    });
});

app.get("/api/public/contract-shares/:token/pdf", function (req, res) {
  pool.query("SELECT contract_id, data FROM contract_shares WHERE token = $1", [req.params.token])
    .then(function (result) {
      var row = result.rows[0];
      if (!row) return res.status(404).send("This link isn't valid, or has been removed.");
      return getContractSignatures(row.contract_id).then(function (signatures) {
        var data = row.data || {};
        data.signatures = signatures;
        renderContractPdf(res, data);
      });
    })
    .catch(function (err) {
      console.error("GET /api/public/contract-shares/:token/pdf failed:", err);
      if (!res.headersSent) res.status(500).send("Could not load this contract");
    });
});

/* Client signing their copy — the only public write onto contract data.
   Scoped by the token's own contract_id, same as the content-approval
   writes above, and capped in size so nobody can stash something large in
   a "signature". Always writes role "client": this endpoint has no way to
   claim to be the developer. */
app.post("/api/public/contract-shares/:token/signature", function (req, res) {
  var name = String((req.body && req.body.name) || "").slice(0, 200);
  var imageData = req.body && req.body.imageData;
  if (!validSignatureImage(imageData)) {
    return res.status(400).json({ error: "That doesn't look like a valid signature image" });
  }
  pool.query("SELECT contract_id FROM contract_shares WHERE token = $1", [req.params.token])
    .then(function (result) {
      var row = result.rows[0];
      if (!row) return res.status(404).json({ error: "not-found" });
      return upsertContractSignature(row.contract_id, "client", name, imageData).then(function (result2) {
        res.json({ ok: true, signedAt: result2.rows[0].signed_at });
      });
    })
    .catch(function (err) {
      console.error("POST /api/public/contract-shares/:token/signature failed:", err);
      if (!res.headersSent) res.status(500).json({ error: "Could not save your signature" });
    });
});

/* ====================== PUBLIC CONTENT APPROVAL LINKS ====================== */
/* Same unguessable-token pattern as contract shares, but this one accepts
   two writes back from an unauthenticated client: approve, or request
   changes. Both are scoped tightly — a token only ever touches posts on
   its own project, and only ones currently in "review" — so holding a link
   never lets someone reach into another project or flip a post that isn't
   actually awaiting their decision. */

function projectClientInfo(projectId) {
  return pool.query("SELECT data FROM app_state WHERE id = 1").then(function (result) {
    var data = (result.rows[0] && result.rows[0].data) || {};
    var projects = data.projects || [];
    var clients = data.clients || [];
    var project = projects.filter(function (p) { return p.id === projectId; })[0];
    if (!project) return { projectName: "", clientName: "", clientAccent: null };
    var client = clients.filter(function (c) { return c.id === project.clientId; })[0];
    return {
      projectName: project.name || "",
      clientName: client ? client.name : "",
      clientAccent: client ? validAccentColor(client.brandColor) : null
    };
  });
}

app.get("/share/content/:token", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "content-approval.html"));
});

app.get("/api/public/content-shares/:token", function (req, res) {
  pool.query("SELECT project_id FROM content_shares WHERE token = $1", [req.params.token])
    .then(function (result) {
      var row = result.rows[0];
      if (!row) return res.status(404).json({ error: "not-found" });
      var projectId = row.project_id;
      return Promise.all([
        projectClientInfo(projectId),
        pool.query(
          "SELECT id, platform, stage, copy_text, scheduled_date, posted_at, updated_at FROM content_posts " +
            "WHERE project_id = $1 AND stage IN ('review', 'approved', 'posted') ORDER BY updated_at DESC",
          [projectId]
        )
      ]).then(function (results) {
        var info = results[0];
        var posts = results[1].rows.map(function (r) {
          return {
            id: r.id, platform: r.platform, stage: r.stage, copy: r.copy_text,
            scheduledDate: r.scheduled_date, postedAt: r.posted_at, updatedAt: r.updated_at
          };
        });
        res.json({ projectName: info.projectName, clientName: info.clientName, clientAccent: info.clientAccent, posts: posts });
      });
    })
    .catch(function (err) {
      console.error("GET /api/public/content-shares/:token failed:", err);
      if (!res.headersSent) res.status(500).json({ error: "Could not load this content queue" });
    });
});

app.post("/api/public/content-shares/:token/posts/:postId/approve", function (req, res) {
  pool.query("SELECT project_id FROM content_shares WHERE token = $1", [req.params.token])
    .then(function (result) {
      var row = result.rows[0];
      if (!row) return res.status(404).json({ error: "not-found" });
      return pool.query(
        "UPDATE content_posts SET stage = 'approved', client_feedback = '', updated_at = now() " +
          "WHERE id = $1 AND project_id = $2 AND stage = 'review' RETURNING id",
        [req.params.postId, row.project_id]
      ).then(function (updateResult) {
        if (!updateResult.rows.length) return res.status(409).json({ error: "This post isn't awaiting approval any more — refresh the page." });
        res.json({ ok: true });
      });
    })
    .catch(function (err) {
      console.error("POST /api/public/content-shares/:token/posts/:postId/approve failed:", err);
      if (!res.headersSent) res.status(500).json({ error: "Could not record your approval" });
    });
});

app.post("/api/public/content-shares/:token/posts/:postId/request-changes", function (req, res) {
  var feedback = String((req.body && req.body.feedback) || "").slice(0, 2000);
  pool.query("SELECT project_id FROM content_shares WHERE token = $1", [req.params.token])
    .then(function (result) {
      var row = result.rows[0];
      if (!row) return res.status(404).json({ error: "not-found" });
      return pool.query(
        "UPDATE content_posts SET stage = 'draft', client_feedback = $1, updated_at = now() " +
          "WHERE id = $2 AND project_id = $3 AND stage = 'review' RETURNING id",
        [feedback, req.params.postId, row.project_id]
      ).then(function (updateResult) {
        if (!updateResult.rows.length) return res.status(409).json({ error: "This post isn't awaiting approval any more — refresh the page." });
        res.json({ ok: true });
      });
    })
    .catch(function (err) {
      console.error("POST /api/public/content-shares/:token/posts/:postId/request-changes failed:", err);
      if (!res.headersSent) res.status(500).json({ error: "Could not send your feedback" });
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

/* ====================== FILE ATTACHMENTS ====================== */

app.get("/api/attachments", function (req, res) {
  var projectId = req.query.projectId;
  if (!projectId) return res.status(400).json({ error: "projectId is required" });
  pool.query(
    "SELECT id, project_id, label, filename, mime_type, size_bytes, created_at " +
      "FROM attachments WHERE project_id = $1 ORDER BY created_at ASC",
    [projectId]
  )
    .then(function (result) {
      res.json(result.rows.map(function (row) {
        return {
          id: row.id,
          projectId: row.project_id,
          label: row.label,
          filename: row.filename,
          mimeType: row.mime_type,
          sizeBytes: row.size_bytes,
          createdAt: row.created_at
        };
      }));
    })
    .catch(function (err) {
      console.error("GET /api/attachments failed:", err);
      res.status(500).json({ error: "Could not load attachments" });
    });
});

app.post("/api/attachments", function (req, res) {
  upload.single("file")(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ error: "File is too large — the limit is 10MB" });
      }
      return res.status(400).json({ error: "Upload failed: " + err.message });
    }
    if (err) {
      console.error("POST /api/attachments upload failed:", err);
      return res.status(500).json({ error: "Upload failed" });
    }

    var projectId = req.body && req.body.projectId;
    var label = (req.body && req.body.label) || "";
    var file = req.file;
    if (!projectId) return res.status(400).json({ error: "projectId is required" });
    if (!file) return res.status(400).json({ error: "No file was uploaded" });

    var id = crypto.randomUUID();
    var filename = file.originalname || "file";
    pool.query(
      "INSERT INTO attachments (id, project_id, label, filename, mime_type, size_bytes, file_data) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7)",
      [id, projectId, label || filename, filename, file.mimetype || "application/octet-stream", file.size, file.buffer]
    )
      .then(function () {
        res.json({
          id: id,
          projectId: projectId,
          label: label || filename,
          filename: filename,
          mimeType: file.mimetype || "application/octet-stream",
          sizeBytes: file.size,
          createdAt: new Date().toISOString()
        });
      })
      .catch(function (err2) {
        console.error("POST /api/attachments insert failed:", err2);
        res.status(500).json({ error: "Could not save the file" });
      });
  });
});

app.get("/api/attachments/:id/download", function (req, res) {
  pool.query(
    "SELECT filename, mime_type, file_data FROM attachments WHERE id = $1",
    [req.params.id]
  )
    .then(function (result) {
      var row = result.rows[0];
      if (!row) return res.status(404).send("Not found");
      var disposition = INLINE_MIME_TYPES[row.mime_type] ? "inline" : "attachment";
      res.setHeader("Content-Type", row.mime_type);
      res.setHeader("Content-Disposition", disposition + '; filename="' + row.filename.replace(/"/g, "") + '"');
      res.send(row.file_data);
    })
    .catch(function (err) {
      console.error("GET /api/attachments/:id/download failed:", err);
      res.status(500).send("Could not load file");
    });
});

app.delete("/api/attachments/:id", function (req, res) {
  pool.query("DELETE FROM attachments WHERE id = $1", [req.params.id])
    .then(function () { res.json({ ok: true }); })
    .catch(function (err) {
      console.error("DELETE /api/attachments/:id failed:", err);
      res.status(500).json({ error: "Could not delete the file" });
    });
});

/* ====================== CONTRACTS: PDF + SHARE LINKS ====================== */
/* Contracts themselves still live inside the app_state JSON blob, same as
   proposals — these routes are stateless helpers layered on top: one
   renders whatever contract fields it's handed as a PDF, the other two
   manage the public share_contracts row that powers a share link. */

app.post("/api/contracts/pdf", function (req, res) {
  var data = req.body;
  if (!data || typeof data !== "object") return res.status(400).json({ error: "Missing contract data" });
  var sigPromise = data.contractId ? getContractSignatures(data.contractId) : Promise.resolve({ developer: null, client: null });
  sigPromise
    .then(function (signatures) {
      data.signatures = signatures;
      try {
        renderContractPdf(res, data);
      } catch (err) {
        console.error("POST /api/contracts/pdf render failed:", err);
        if (!res.headersSent) res.status(500).json({ error: "Could not generate the PDF" });
      }
    })
    .catch(function (err) {
      console.error("POST /api/contracts/pdf failed:", err);
      if (!res.headersSent) res.status(500).json({ error: "Could not generate the PDF" });
    });
});

app.get("/api/contracts/:id/signatures", function (req, res) {
  getContractSignatures(req.params.id)
    .then(function (signatures) { res.json(signatures); })
    .catch(function (err) {
      console.error("GET /api/contracts/:id/signatures failed:", err);
      res.status(500).json({ error: "Could not load signatures" });
    });
});

app.post("/api/contracts/:id/signatures", function (req, res) {
  var role = req.body && req.body.role;
  var name = String((req.body && req.body.name) || "").slice(0, 200);
  var imageData = req.body && req.body.imageData;
  if (role !== "developer" && role !== "client") return res.status(400).json({ error: "Invalid role" });
  if (!validSignatureImage(imageData)) {
    return res.status(400).json({ error: "That doesn't look like a valid signature image" });
  }
  upsertContractSignature(req.params.id, role, name, imageData)
    .then(function (result) { res.json({ ok: true, signedAt: result.rows[0].signed_at }); })
    .catch(function (err) {
      console.error("POST /api/contracts/:id/signatures failed:", err);
      res.status(500).json({ error: "Could not save the signature" });
    });
});

app.delete("/api/contracts/:id/signatures/:role", function (req, res) {
  var role = req.params.role;
  if (role !== "developer" && role !== "client") return res.status(400).json({ error: "Invalid role" });
  pool.query("DELETE FROM contract_signatures WHERE contract_id = $1 AND role = $2", [req.params.id, role])
    .then(function () { res.json({ ok: true }); })
    .catch(function (err) {
      console.error("DELETE /api/contracts/:id/signatures/:role failed:", err);
      res.status(500).json({ error: "Could not clear that signature" });
    });
});

app.delete("/api/contracts/:id/signatures", function (req, res) {
  pool.query("DELETE FROM contract_signatures WHERE contract_id = $1", [req.params.id])
    .then(function () { res.json({ ok: true }); })
    .catch(function (err) {
      console.error("DELETE /api/contracts/:id/signatures failed:", err);
      res.status(500).json({ error: "Could not clear signatures" });
    });
});

app.post("/api/contract-shares", function (req, res) {
  var contractId = req.body && req.body.contractId;
  var data = req.body && req.body.data;
  if (!contractId || !data || typeof data !== "object") {
    return res.status(400).json({ error: "contractId and data are required" });
  }
  var newToken = crypto.randomUUID();
  pool.query(
    "INSERT INTO contract_shares (token, contract_id, data) VALUES ($1, $2, $3) " +
      "ON CONFLICT (contract_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now() " +
      "RETURNING token",
    [newToken, contractId, data]
  )
    .then(function (result) {
      res.json({ token: result.rows[0].token });
    })
    .catch(function (err) {
      console.error("POST /api/contract-shares failed:", err);
      res.status(500).json({ error: "Could not create the share link" });
    });
});

app.delete("/api/contract-shares/:contractId", function (req, res) {
  pool.query("DELETE FROM contract_shares WHERE contract_id = $1", [req.params.contractId])
    .then(function () { res.json({ ok: true }); })
    .catch(function (err) {
      console.error("DELETE /api/contract-shares/:contractId failed:", err);
      res.status(500).json({ error: "Could not stop sharing" });
    });
});

/* ====================== CONTENT POSTS (client social pipeline) ====================== */
/* Posts live in their own table (see ensureSchema for why) and are fetched
   per-project on demand, same shape as attachments. */

var CONTENT_STAGES = ["idea", "draft", "review", "approved", "posted"];
function isValidStage(s) { return CONTENT_STAGES.indexOf(s) !== -1; }
function rowToPost(r) {
  return {
    id: r.id, projectId: r.project_id, platform: r.platform, stage: r.stage,
    copy: r.copy_text, notes: r.notes, scheduledDate: r.scheduled_date,
    clientFeedback: r.client_feedback, postedAt: r.posted_at,
    createdAt: r.created_at, updatedAt: r.updated_at
  };
}

app.get("/api/content-posts", function (req, res) {
  var projectId = req.query.projectId;
  if (!projectId) return res.status(400).json({ error: "projectId is required" });
  pool.query("SELECT * FROM content_posts WHERE project_id = $1 ORDER BY created_at ASC", [projectId])
    .then(function (result) { res.json(result.rows.map(rowToPost)); })
    .catch(function (err) {
      console.error("GET /api/content-posts failed:", err);
      res.status(500).json({ error: "Could not load posts" });
    });
});

app.post("/api/content-posts", function (req, res) {
  var b = req.body || {};
  var projectId = b.projectId;
  if (!projectId) return res.status(400).json({ error: "projectId is required" });
  var stage = isValidStage(b.stage) ? b.stage : "idea";
  var id = crypto.randomUUID();
  pool.query(
    "INSERT INTO content_posts (id, project_id, platform, stage, copy_text, notes, scheduled_date) " +
      "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
    [id, projectId, String(b.platform || ""), stage, String(b.copy || ""), String(b.notes || ""), String(b.scheduledDate || "")]
  )
    .then(function (result) { res.json(rowToPost(result.rows[0])); })
    .catch(function (err) {
      console.error("POST /api/content-posts failed:", err);
      res.status(500).json({ error: "Could not create the post" });
    });
});

app.put("/api/content-posts/:id", function (req, res) {
  var b = req.body || {};
  var stage = isValidStage(b.stage) ? b.stage : "idea";
  pool.query(
    "UPDATE content_posts SET " +
      "platform = $1, stage = $2, copy_text = $3, notes = $4, scheduled_date = $5, client_feedback = $6, " +
      "posted_at = CASE WHEN $2 = 'posted' AND posted_at IS NULL THEN now() WHEN $2 != 'posted' THEN NULL ELSE posted_at END, " +
      "updated_at = now() " +
      "WHERE id = $7 RETURNING *",
    [String(b.platform || ""), stage, String(b.copy || ""), String(b.notes || ""), String(b.scheduledDate || ""), String(b.clientFeedback || ""), req.params.id]
  )
    .then(function (result) {
      if (!result.rows.length) return res.status(404).json({ error: "Post not found" });
      res.json(rowToPost(result.rows[0]));
    })
    .catch(function (err) {
      console.error("PUT /api/content-posts/:id failed:", err);
      res.status(500).json({ error: "Could not update the post" });
    });
});

app.delete("/api/content-posts/:id", function (req, res) {
  pool.query("DELETE FROM content_posts WHERE id = $1", [req.params.id])
    .then(function () { res.json({ ok: true }); })
    .catch(function (err) {
      console.error("DELETE /api/content-posts/:id failed:", err);
      res.status(500).json({ error: "Could not delete the post" });
    });
});

app.get("/api/content-shares/:projectId", function (req, res) {
  pool.query("SELECT token FROM content_shares WHERE project_id = $1", [req.params.projectId])
    .then(function (result) {
      if (!result.rows.length) return res.status(404).json({ error: "not-found" });
      res.json({ token: result.rows[0].token });
    })
    .catch(function (err) {
      console.error("GET /api/content-shares/:projectId failed:", err);
      res.status(500).json({ error: "Could not load share status" });
    });
});

app.post("/api/content-shares", function (req, res) {
  var projectId = req.body && req.body.projectId;
  if (!projectId) return res.status(400).json({ error: "projectId is required" });
  var newToken = crypto.randomUUID();
  pool.query(
    "INSERT INTO content_shares (token, project_id) VALUES ($1, $2) " +
      "ON CONFLICT (project_id) DO UPDATE SET project_id = EXCLUDED.project_id " +
      "RETURNING token",
    [newToken, projectId]
  )
    .then(function (result) { res.json({ token: result.rows[0].token }); })
    .catch(function (err) {
      console.error("POST /api/content-shares failed:", err);
      res.status(500).json({ error: "Could not create the share link" });
    });
});

app.delete("/api/content-shares/:projectId", function (req, res) {
  pool.query("DELETE FROM content_shares WHERE project_id = $1", [req.params.projectId])
    .then(function () { res.json({ ok: true }); })
    .catch(function (err) {
      console.error("DELETE /api/content-shares/:projectId failed:", err);
      res.status(500).json({ error: "Could not stop sharing" });
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
