# SMART DRIVE GUARD

Responsive educational prototype for a vehicle-access verification project.

## Features
- Email/password account registration and login (owner or driver role)
- Passkey/WebAuthn registration and login using the device's supported user verification (biometric, PIN, or security key)
- Owner dashboard and vehicle registration
- Add drivers and family members; upload sample licence documents
- Owner approval/rejection
- Three-action dummy biometric management: create, edit/enable/disable, delete
- Demonstration access decision: biometric result AND licence expiry check AND owner approval
- Access history
- Responsive layout for laptop and mobile browsers

## Important limitations
- This is an educational demonstration, not a production vehicle security system.
- A browser passkey confirms that the device's configured authenticator approved the user. It does not identify the human by legal name, prove that the authenticator belongs to a particular licence holder, or provide raw fingerprint/face data to the website.
- Dummy biometric profiles are simulated database flags. They are not government biometric records and must be labelled as simulated.
- Licence uploads are stored as demonstration documents. The app does not validate a licence with a government authority.
- HC-05 uses Bluetooth Classic SPP. Normal browser Web Bluetooth does not support HC-05. This repository therefore does not transmit commands to HC-05 or control a real ignition. Use the on-screen result for the demo; for hardware integration use a separate Android Bluetooth bridge or change to compatible BLE hardware.
- Do not connect this prototype to a real vehicle.

## Requirements
- Node.js 20 or newer recommended
- npm
- Chrome/Edge/Firefox current version

## Run locally
```bash
npm install
cp .env.example .env
```
On Windows PowerShell:
```powershell
Copy-Item .env.example .env
```

Then:
```bash
npm run dev
```
Open http://localhost:5173

The backend runs on http://localhost:3001. Vite proxies `/api` and `/uploads`.

## First use
1. Register an account with role `owner`.
2. Register a passkey from the browser/device after signing in (passkey registration UI can be added through the account screen; see note below).
3. Add a vehicle.
4. Create a dummy biometric profile.
5. Add a driver or family member and associate the profile.
6. Approve the driver.
7. Open the verification demonstration, select vehicle and driver, tick the simulated local biometric test, and run the check.

### Passkey setup endpoint
The backend includes WebAuthn registration endpoints. For a complete UI flow, call:
- `POST /api/passkey/register-options` (authenticated)
- `startRegistration({ optionsJSON })` in the browser
- `POST /api/passkey/register-verify` with the returned credential

Passkey sign-in flow:
- `POST /api/passkey/auth-options` with `{ "email": "..." }`
- `startAuthentication({ optionsJSON })`
- `POST /api/passkey/auth-verify` with the credential response

The default demo UI provides password login and passkey sign-in. To register a passkey, add a button after login that runs the registration flow above. This avoids silently enrolling a device without the user's consent.

## Production deployment checklist
Before public deployment:
- Replace the development session secret with a long random secret.
- Use HTTPS and set secure session cookies.
- Configure `RP_ID` to your real domain and `ORIGIN` to your exact HTTPS origin.
- Replace the JSON file database with Firestore/PostgreSQL and use a persistent private file store.
- Add CSRF protection, rate limiting, account recovery, audit logging and strict role-based authorization.
- Add private upload authorization; do not expose licence documents as public static files.
- Add server-side licence verification only through an authorised source.
- Review privacy and data-protection requirements.

## GitHub
Create a new empty repository on GitHub, then:
```bash
git init
git add .
git commit -m "Initial SMART DRIVE GUARD web prototype"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/smart-drive-guard.git
git push -u origin main
```
