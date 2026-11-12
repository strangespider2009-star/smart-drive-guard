
import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import multer from "multer";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";

// --------------------------------------------------
// INITIAL CONFIGURATION
// --------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const PORT = process.env.PORT || 3001;
const RP_ID = process.env.RP_ID || "localhost";
const ORIGIN = process.env.ORIGIN || "http://localhost:5173";

const isProduction = process.env.NODE_ENV === "production";

if (isProduction) {
  app.set("trust proxy", 1);
}

// --------------------------------------------------
// DATABASE AND UPLOAD DIRECTORIES
// --------------------------------------------------

const DATA_FILE = path.join(__dirname, "data.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify(
      {
        users: [],
        vehicles: [],
        drivers: [],
        biometrics: [],
        logs: []
      },
      null,
      2
    )
  );
}

const readDB = () => {
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
};

const writeDB = (db) => {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
};

const id = () => crypto.randomUUID();

// --------------------------------------------------
// MIDDLEWARE
// --------------------------------------------------

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    name: "sdg.sid",
    secret:
      process.env.SESSION_SECRET ||
      "development-only-change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);

// Demo uploads only.
// Do not upload real driving licence documents.
app.use("/uploads", express.static(UPLOAD_DIR));

const upload = multer({
  dest: UPLOAD_DIR,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (_req, file, cb) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "application/pdf"
    ];

    const valid = allowedTypes.includes(file.mimetype);

    if (!valid) {
      return cb(
        new Error("Only JPG, PNG or PDF files are allowed.")
      );
    }

    cb(null, true);
  }
});

// --------------------------------------------------
// AUTHENTICATION HELPERS
// --------------------------------------------------

function currentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return (
    readDB().users.find(
      (user) => user.id === req.session.userId
    ) || null
  );
}

function requireAuth(req, res, next) {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please sign in."
    });
  }

  req.user = user;
  next();
}

function publicUser(user) {
  const {
    passwordHash,
    passkeys,
    ...safeUser
  } = user;

  return safeUser;
}

function ownerOnly(req, res, next) {
  if (req.user.role !== "owner") {
    return res.status(403).json({
      error: "Owner permission required."
    });
  }

  next();
}

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    name: "SMART DRIVE GUARD API"
  });
});

// --------------------------------------------------
// USER REGISTRATION
// --------------------------------------------------

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      role
    } = req.body || {};

    if (
      !name ||
      !email ||
      !password ||
      !["owner", "driver"].includes(role)
    ) {
      return res.status(400).json({
        error: "Enter name, email, password and role."
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters."
      });
    }

    const db = readDB();

    if (
      db.users.some(
        (user) =>
          user.email.toLowerCase() ===
          String(email).toLowerCase()
      )
    ) {
      return res.status(409).json({
        error: "Email already registered."
      });
    }

    const user = {
      id: id(),
      name,
      email: String(email).toLowerCase(),
      role,
      passwordHash: await bcrypt.hash(password, 12),
      passkeys: [],
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    writeDB(db);

    req.session.userId = user.id;

    res.json({
      user: publicUser(user)
    });
  } catch (error) {
    res.status(500).json({
      error: "Registration failed."
    });
  }
});

// --------------------------------------------------
// USER LOGIN
// --------------------------------------------------

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body || {};

    const user = readDB().users.find(
      (u) =>
        u.email === String(email || "").toLowerCase()
    );

    if (
      !user ||
      !(await bcrypt.compare(
        password || "",
        user.passwordHash
      ))
    ) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    req.session.userId = user.id;

    res.json({
      user: publicUser(user)
    });
  } catch (error) {
    res.status(500).json({
      error: "Login failed."
    });
  }
});

// --------------------------------------------------
// LOGOUT AND CURRENT USER
// --------------------------------------------------

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sdg.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", (req, res) => {
  const user = currentUser(req);

  res.json({
    user: user ? publicUser(user) : null
  });
});

// --------------------------------------------------
// PASSKEY REGISTRATION
// --------------------------------------------------

app.post(
  "/api/passkey/register-options",
  requireAuth,
  async (req, res) => {
    try {
      const options = await generateRegistrationOptions({
        rpName: "SMART DRIVE GUARD",
        rpID: RP_ID,
        userName: req.user.email,
        userDisplayName: req.user.name,
        userID: new Uint8Array(Buffer.from(req.user.id)),
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required"
        },
        excludeCredentials: (
          req.user.passkeys || []
        ).map((p) => ({
          id: p.id,
          transports: p.transports
        }))
      });

      req.session.regChallenge = options.challenge;

      res.json(options);
    } catch (error) {
      res.status(500).json({
        error: "Could not generate passkey options."
      });
    }
  }
);

app.post(
  "/api/passkey/register-verify",
  requireAuth,
  async (req, res) => {
    try {
      const verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: req.session.regChallenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true
      });

      if (
        !verification.verified ||
        !verification.registrationInfo
      ) {
        return res.status(400).json({
          error: "Passkey registration was not verified."
        });
      }

      const info = verification.registrationInfo;
      const db = readDB();

      const user = db.users.find(
        (u) => u.id === req.user.id
      );

      user.passkeys ||= [];

      user.passkeys.push({
        id: info.credential.id,
        publicKey: Buffer.from(
          info.credential.publicKey
        ).toString("base64"),
        counter: info.credential.counter,
        transports: req.body.response?.transports || []
      });

      writeDB(db);

      delete req.session.regChallenge;

      res.json({ verified: true });
    } catch (error) {
      res.status(400).json({
        error: error.message || "Could not register passkey."
      });
    }
  }
);

// --------------------------------------------------
// PASSKEY LOGIN
// --------------------------------------------------

app.post("/api/passkey/auth-options", async (req, res) => {
  try {
    const email = String(
      req.body.email || ""
    ).toLowerCase();

    const user = readDB().users.find(
      (u) => u.email === email
    );

    if (!user || !(user.passkeys || []).length) {
      return res.status(404).json({
        error: "No passkey registered for this account. Sign in with password and register one first."
      });
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: user.passkeys.map((p) => ({
        id: p.id,
        transports: p.transports
      })),
      userVerification: "required"
    });

    req.session.authChallenge = options.challenge;
    req.session.passkeyUserId = user.id;

    res.json(options);
  } catch (error) {
    res.status(500).json({
      error: "Could not generate authentication options."
    });
  }
});

app.post("/api/passkey/auth-verify", async (req, res) => {
  try {
    const db = readDB();

    const user = db.users.find(
      (u) => u.id === req.session.passkeyUserId
    );

    if (!user) {
      return res.status(401).json({
        error: "Passkey account not found."
      });
    }

    const credential = (user.passkeys || []).find(
      (p) => p.id === req.body.id
    );

    if (!credential) {
      return res.status(401).json({
        error: "Unknown passkey."
      });
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: req.session.authChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: credential.id,
        publicKey: new Uint8Array(
          Buffer.from(credential.publicKey, "base64")
        ),
        counter: credential.counter,
        transports: credential.transports
      },
      requireUserVerification: true
    });

    if (!verification.verified) {
      return res.status(401).json({
        error: "Passkey verification failed."
      });
    }

    credential.counter =
      verification.authenticationInfo.newCounter;

    writeDB(db);

    req.session.userId = user.id;

    delete req.session.authChallenge;
    delete req.session.passkeyUserId;

    res.json({
      user: publicUser(user),
      verified: true
    });
  } catch (error) {
    res.status(400).json({
      error: error.message || "Passkey verification failed."
    });
  }
});

// --------------------------------------------------
// DASHBOARD
// --------------------------------------------------

app.get("/api/dashboard", requireAuth, (req, res) => {
  const db = readDB();

  const vehicles = db.vehicles.filter(
    (v) => v.ownerId === req.user.id
  );

  const drivers = db.drivers.filter(
    (d) =>
      d.ownerId === req.user.id ||
      d.userId === req.user.id
  );

  const biometrics =
    req.user.role === "owner"
      ? db.biometrics.filter(
          (b) => b.ownerId === req.user.id
        )
      : [];

  const logs = db.logs
    .filter(
      (l) =>
        l.ownerId === req.user.id ||
        l.userId === req.user.id
    )
    .slice(-20)
    .reverse();

  res.json({
    vehicles,
    drivers,
    biometrics,
    logs
  });
});

// --------------------------------------------------
// VEHICLE MANAGEMENT
// --------------------------------------------------

app.post(
  "/api/vehicles",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const {
      vehicleName,
      registration
    } = req.body || {};

    if (!vehicleName) {
      return res.status(400).json({
        error: "Vehicle name is required."
      });
    }

    const db = readDB();

    const vehicle = {
      id: id(),
      vehicleName,
      registration: registration || "DEMO-REG",
      ownerId: req.user.id,
      bluetoothName: "HC-05",
      createdAt: new Date().toISOString()
    };

    db.vehicles.push(vehicle);
    writeDB(db);

    res.json({ vehicle });
  }
);

// --------------------------------------------------
// DRIVER MANAGEMENT
// --------------------------------------------------

app.post(
  "/api/drivers",
  requireAuth,
  ownerOnly,
  upload.single("licence"),
  (req, res) => {
    const {
      name,
      email,
      phone,
      licenceNumber,
      expiryDate,
      relationship,
      biometricProfileId,
      vehicleId,
      kind
    } = req.body;

    if (
      !name ||
      !licenceNumber ||
      !expiryDate ||
      !vehicleId
    ) {
      return res.status(400).json({
        error: "Complete the required driver and licence fields."
      });
    }

    const db = readDB();

    const vehicle = db.vehicles.find(
      (v) =>
        v.id === vehicleId &&
        v.ownerId === req.user.id
    );

    if (!vehicle) {
      return res.status(400).json({
        error: "Select one of your vehicles."
      });
    }

    const profile = db.biometrics.find(
      (b) =>
        b.id === biometricProfileId &&
        b.ownerId === req.user.id
    );

    const driver = {
      id: id(),
      ownerId: req.user.id,
      vehicleId,
      name,
      email: email || "",
      phone: phone || "",
      licenceNumber,
      expiryDate,
      relationship: relationship || "",
      kind: kind === "family" ? "family" : "driver",
      licenceFile: req.file
        ? `/uploads/${req.file.filename}`
        : null,
      biometricProfileId: profile?.id || null,
      ownerApproved: false,
      status: "pending",
      createdAt: new Date().toISOString()
    };

    db.drivers.push(driver);
    writeDB(db);

    res.json({ driver });
  }
);

app.patch(
  "/api/drivers/:id/approval",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const db = readDB();

    const driver = db.drivers.find(
      (d) =>
        d.id === req.params.id &&
        d.ownerId === req.user.id
    );

    if (!driver) {
      return res.status(404).json({
        error: "Driver not found."
      });
    }

    driver.ownerApproved = Boolean(req.body.approved);

    driver.status = driver.ownerApproved
      ? "approved"
      : "rejected";

    writeDB(db);

    res.json({ driver });
  }
);

app.delete(
  "/api/drivers/:id",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const db = readDB();

    db.drivers = db.drivers.filter(
      (d) =>
        !(
          d.id === req.params.id &&
          d.ownerId === req.user.id
        )
    );

    writeDB(db);

    res.json({ ok: true });
  }
);

// --------------------------------------------------
// BIOMETRIC DEMO MANAGEMENT
// --------------------------------------------------

app.post(
  "/api/biometrics",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const {
      profileName,
      fingerprintRegistered,
      faceRegistered,
      simulatedMatch
    } = req.body || {};

    if (!profileName) {
      return res.status(400).json({
        error: "Profile name is required."
      });
    }

    const db = readDB();

    const profile = {
      id: id(),
      ownerId: req.user.id,
      profileName,
      fingerprintRegistered: !!fingerprintRegistered,
      faceRegistered: !!faceRegistered,
      simulatedMatch: !!simulatedMatch,
      status: "active",
      createdAt: new Date().toISOString()
    };

    db.biometrics.push(profile);
    writeDB(db);

    res.json({ profile });
  }
);

app.patch(
  "/api/biometrics/:id",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const db = readDB();

    const profile = db.biometrics.find(
      (p) =>
        p.id === req.params.id &&
        p.ownerId === req.user.id
    );

    if (!profile) {
      return res.status(404).json({
        error: "Profile not found."
      });
    }

    for (const key of [
      "profileName",
      "fingerprintRegistered",
      "faceRegistered",
      "simulatedMatch",
      "status"
    ]) {
      if (key in req.body) {
        profile[key] = req.body[key];
      }
    }

    writeDB(db);

    res.json({ profile });
  }
);

app.delete(
  "/api/biometrics/:id",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const db = readDB();

    db.biometrics = db.biometrics.filter(
      (p) =>
        !(
          p.id === req.params.id &&
          p.ownerId === req.user.id
        )
    );

    writeDB(db);

    res.json({ ok: true });
  }
);

// --------------------------------------------------
// DEMONSTRATION ACCESS CHECK
// --------------------------------------------------

app.post(
  "/api/access/check",
  requireAuth,
  async (req, res) => {
    const {
      driverId,
      vehicleId,
      localBiometricPassed
    } = req.body || {};

    const db = readDB();

    const driver = db.drivers.find(
      (d) =>
        d.id === driverId &&
        d.ownerId === req.user.id
    );

    const vehicle = db.vehicles.find(
      (v) =>
        v.id === vehicleId &&
        v.ownerId === req.user.id
    );

    const profile = driver?.biometricProfileId
      ? db.biometrics.find(
          (b) =>
            b.id === driver.biometricProfileId &&
            b.ownerId === req.user.id
        )
      : null;

    const biometricResult =
      !!localBiometricPassed &&
      !!profile &&
      profile.status === "active" &&
      profile.fingerprintRegistered &&
      profile.faceRegistered &&
      profile.simulatedMatch;

    const licenceResult =
      !!driver &&
      new Date(driver.expiryDate + "T23:59:59") >=
        new Date();

    const ownerApproval = !!driver?.ownerApproved;

    const granted =
      !!vehicle &&
      biometricResult &&
      licenceResult &&
      ownerApproval;

    const log = {
      id: id(),
      ownerId: req.user.id,
      driverId,
      vehicleId,
      biometricResult,
      licenceResult,
      ownerApproval,
      accessGranted: granted,
      createdAt: new Date().toISOString()
    };

    db.logs.push(log);
    writeDB(db);

    res.json({
      biometricResult,
      licenceResult,
      ownerApproval,
      accessGranted: granted,
      logic: [
        biometricResult,
        licenceResult,
        ownerApproval
      ]
    });
  }
);

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((err, _req, res, _next) => {
  console.error("Server error:", err);

  res.status(400).json({
    error: err.message || "Request failed."
  });
});

// --------------------------------------------------
// START SERVER - ONLY ONE LISTENER
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `SMART DRIVE GUARD API listening on port ${PORT}`
  );
});
