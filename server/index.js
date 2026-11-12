
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
// 1. BASIC CONFIGURATION
// --------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const DIST_DIR = path.resolve(__dirname, "../dist");
const DATA_FILE = path.join(__dirname, "data.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");

const RP_ID = process.env.RP_ID || "localhost";
const ORIGIN = process.env.ORIGIN || "http://localhost:5173";

if (IS_PRODUCTION) {
  if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET must be configured in production.");
  }

  if (!process.env.RP_ID || !process.env.ORIGIN) {
    throw new Error("RP_ID and ORIGIN must be configured in production.");
  }

  const productionOrigin = new URL(ORIGIN);

  if (
    productionOrigin.protocol !== "https:" ||
    productionOrigin.hostname !== RP_ID
  ) {
    throw new Error("WebAuthn ORIGIN and RP_ID do not match.");
  }

  app.set("trust proxy", 1);
}

// --------------------------------------------------
// 2. DATABASE INITIALIZATION
// --------------------------------------------------

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
  const tempFile = `${DATA_FILE}.tmp`;

  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2));
  fs.renameSync(tempFile, DATA_FILE);
};

const id = () => crypto.randomUUID();

// --------------------------------------------------
// 3. EXPRESS MIDDLEWARE
// --------------------------------------------------

app.disable("x-powered-by");

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
      secure: IS_PRODUCTION,
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);

// --------------------------------------------------
// 4. FILE UPLOAD CONFIGURATION
// --------------------------------------------------

const upload = multer({
  dest: UPLOAD_DIR,

  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1
  },

  fileFilter: (_req, file, cb) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "application/pdf"
    ];

    const allowedExtensions = [".jpg", ".jpeg", ".png", ".pdf"];

    const extension = path.extname(file.originalname).toLowerCase();

    const valid =
      allowedTypes.includes(file.mimetype) &&
      allowedExtensions.includes(extension);

    if (!valid) {
      return cb(
        new Error("Only JPG, PNG or PDF files are allowed.")
      );
    }

    cb(null, true);
  }
});

// --------------------------------------------------
// 5. AUTHENTICATION HELPERS
// --------------------------------------------------

function currentUser(req) {
  if (!req.session.userId) return null;

  const db = readDB();

  return (
    db.users.find((u) => u.id === req.session.userId) || null
  );
}

function requireAuth(req, res, next) {
  try {
    const user = currentUser(req);

    if (!user) {
      return res.status(401).json({
        error: "Please sign in."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
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
// 6. HEALTH CHECK
// --------------------------------------------------

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    name: "SMART DRIVE GUARD API"
  });
});

// --------------------------------------------------
// 7. USER REGISTRATION
// --------------------------------------------------

app.post("/api/auth/register", async (req, res, next) => {
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

    const normalizedEmail = String(email).trim().toLowerCase();

    const db = readDB();

    if (
      db.users.some(
        (u) => u.email.toLowerCase() === normalizedEmail
      )
    ) {
      return res.status(409).json({
        error: "Email already registered."
      });
    }

    const user = {
      id: id(),
      name: String(name).trim(),
      email: normalizedEmail,
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
    next(error);
  }
});

// --------------------------------------------------
// 8. USER LOGIN
// --------------------------------------------------

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    const normalizedEmail = String(email || "")
      .trim()
      .toLowerCase();

    const user = readDB().users.find(
      (u) => u.email === normalizedEmail
    );

    if (
      !user ||
      !(await bcrypt.compare(password || "", user.passwordHash))
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
    next(error);
  }
});

// --------------------------------------------------
// 9. LOGOUT
// --------------------------------------------------

app.post("/api/auth/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie("sdg.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PRODUCTION
    });

    res.json({ ok: true });
  });
});

// --------------------------------------------------
// 10. CURRENT USER
// --------------------------------------------------

app.get("/api/me", (req, res) => {
  const user = currentUser(req);

  res.json({
    user: user ? publicUser(user) : null
  });
});

// --------------------------------------------------
// 11. PASSKEY REGISTRATION OPTIONS
// --------------------------------------------------

app.post(
  "/api/passkey/register-options",
  requireAuth,
  async (req, res, next) => {
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

        excludeCredentials: (req.user.passkeys || []).map((p) => ({
          id: p.id,
          transports: p.transports
        }))
      });

      req.session.regChallenge = options.challenge;

      res.json(options);
    } catch (error) {
      next(error);
    }
  }
);

// --------------------------------------------------
// 12. PASSKEY REGISTRATION VERIFICATION
// --------------------------------------------------

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

      if (!user) {
        return res.status(404).json({
          error: "User not found."
        });
      }

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
// 13. PASSKEY LOGIN OPTIONS
// --------------------------------------------------

app.post(
  "/api/passkey/auth-options",
  async (req, res, next) => {
    try {
      const email = String(req.body.email || "")
        .trim()
        .toLowerCase();

      const user = readDB().users.find(
        (u) => u.email === email
      );

      if (!user || !(user.passkeys || []).length) {
        return res.status(404).json({
          error:
            "No passkey registered for this account. Sign in with password and register one first."
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
      next(error);
    }
  }
);

// --------------------------------------------------
// 14. PASSKEY LOGIN VERIFICATION
// --------------------------------------------------

app.post(
  "/api/passkey/auth-verify",
  async (req, res) => {
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
  }
);

// --------------------------------------------------
// 15. DASHBOARD
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
// 16. ADD VEHICLE
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
// 17. ADD DRIVER OR FAMILY MEMBER
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

    const driverId = id();

    const driver = {
      id: driverId,
      ownerId: req.user.id,
      vehicleId,

      name,
      email: email || "",
      phone: phone || "",

      licenceNumber,
      expiryDate,

      relationship: relationship || "",

      kind: kind === "family" ? "family" : "driver",

      // Licence files are accessed through an
      // authenticated endpoint, not public static hosting.
      licenceFile: req.file
        ? `/api/drivers/${driverId}/licence`
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

// --------------------------------------------------
// 18. SECURE LICENCE FILE ACCESS
// --------------------------------------------------

app.get(
  "/api/drivers/:id/licence",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const db = readDB();

    const driver = db.drivers.find(
      (d) =>
        d.id === req.params.id &&
        d.ownerId === req.user.id
    );

    if (!driver || !driver.licenceFile) {
      return res.status(404).json({
        error: "Licence file not found."
      });
    }

    const filename = path.basename(driver.licenceFile);

    const filePath = path.join(UPLOAD_DIR, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        error: "Uploaded file is unavailable."
      });
    }

    res.setHeader("Cache-Control", "private, no-store");

    res.sendFile(filePath);
  }
);

// --------------------------------------------------
// 19. DRIVER APPROVAL
// --------------------------------------------------

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

// --------------------------------------------------
// 20. DELETE DRIVER
// --------------------------------------------------

app.delete(
  "/api/drivers/:id",
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

    if (driver.licenceFile) {
      const filename = path.basename(driver.licenceFile);
      const filePath = path.join(UPLOAD_DIR, filename);

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    db.drivers = db.drivers.filter(
      (d) => d.id !== req.params.id
    );

    writeDB(db);

    res.json({ ok: true });
  }
);

// --------------------------------------------------
// 21. ADD DUMMY BIOMETRIC PROFILE
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

// --------------------------------------------------
// 22. UPDATE BIOMETRIC PROFILE
// --------------------------------------------------

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

    const allowedFields = [
      "profileName",
      "fingerprintRegistered",
      "faceRegistered",
      "simulatedMatch",
      "status"
    ];

    for (const key of allowedFields) {
      if (key in req.body) {
        profile[key] = req.body[key];
      }
    }

    writeDB(db);

    res.json({ profile });
  }
);

// --------------------------------------------------
// 23. DELETE BIOMETRIC PROFILE
// --------------------------------------------------

app.delete(
  "/api/biometrics/:id",
  requireAuth,
  ownerOnly,
  (req, res) => {
    const db = readDB();

    db.biometrics = db.biometrics.filter(
      (p) =>
        !(p.id === req.params.id &&
          p.ownerId === req.user.id)
    );

    writeDB(db);

    res.json({ ok: true });
  }
);

// --------------------------------------------------
// 24. DEMONSTRATION ACCESS CHECK
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
      new Date(driver.expiryDate + "T23:59:59") >= new Date();

    const ownerApproval = !!driver?.ownerApproved;

    const granted =
      !!vehicle &&
      !!driver &&
      driver.vehicleId === vehicle.id &&
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
// 25. UNKNOWN API ROUTES
// --------------------------------------------------

app.use("/api", (_req, res) => {
  res.status(404).json({
    error: "API endpoint not found."
  });
});

// --------------------------------------------------
// 26. SERVE REACT PRODUCTION BUILD
// --------------------------------------------------

app.use(
  express.static(DIST_DIR, {
    index: false
  })
);

// React client-side routing fallback.
// Express 4 syntax.

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return next();
  }

  const indexFile = path.join(DIST_DIR, "index.html");

  if (!fs.existsSync(indexFile)) {
    return res.status(503).send(
      "Frontend build not found. Run npm run build."
    );
  }

  res.sendFile(indexFile);
});

// --------------------------------------------------
// 27. GLOBAL ERROR HANDLER
// --------------------------------------------------

app.use((err, req, res, _next) => {
  console.error(err);

  if (res.headersSent) return;

  const status =
    err instanceof multer.MulterError ? 400 : 500;

  res.status(status).json({
    error:
      status === 400
        ? err.message
        : "Internal server error."
  });
});

// --------------------------------------------------
// 28. START SERVER - ONLY ONCE
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `SMART DRIVE GUARD running on port ${PORT}`
  );

  console.log(
    `Environment: ${IS_PRODUCTION ? "production" : "development"}`
  );

  console.log(
    `Frontend build: ${fs.existsSync(path.join(DIST_DIR, "index.html")) ? "available" : "not found"}`
  );
});
