// server.js — deploy this as a small Render web service.
//
// This replaces the broken pkpass-signing code that was living inside the
// Cloudflare Worker (parsePKCS12/buildPKCS7Signature were stubs — Workers
// can't do the ASN.1/PKCS#7 construction Apple Wallet needs). This service
// does the real signing using the `passkit-generator` library, which wraps
// OpenSSL-equivalent signing correctly.
//
// ── One-time setup ──────────────────────────────────────────────────
// 1. In the Apple Developer portal (under Rizlane Sefrioui's account):
//      Certificates, IDs & Profiles → Identifiers → Pass Type IDs
//      → create one, e.g. pass.ma.8848club.membership
//    Then Certificates → + → Pass Type ID Certificate → select it →
//    upload a CSR (Keychain Access → Certificate Assistant → Request a
//    Certificate from a CA) → download the generated .cer
// 2. Import the .cer into Keychain (double-click it), find it under
//    "My Certificates", right-click → Export → save as Certificates.p12
//    with a passphrase you'll remember.
// 3. Download Apple's WWDR (Worldwide Developer Relations) intermediate
//    certificate: https://www.apple.com/certificateauthority/ → "Worldwide
//    Developer Relations - G4" (or current) → AppleWWDRCAG4.cer
// 4. Convert everything to PEM (run locally, e.g. on the Mac you'd use
//    for Xcode dev):
//      openssl pkcs12 -in Certificates.p12 -nocerts -out signerKey.pem -passout pass:YOUR_PASSPHRASE
//      openssl pkcs12 -in Certificates.p12 -clcerts -nokeys -out signerCert.pem -passout pass:YOUR_PASSPHRASE
//      openssl x509 -inform der -in AppleWWDRCAG4.cer -out wwdr.pem
// 5. Base64 the three PEM files (`base64 -i signerKey.pem | pbcopy` etc.)
//    and set them as Render environment variables (see below).
// 6. Fill in models/membership.pass/pass.json with your real
//    passTypeIdentifier + teamIdentifier, and drop real icon.png /
//    icon@2x.png / logo.png / logo@2x.png (and optionally strip.png)
//    into models/membership.pass/.
//
// ── Render environment variables ────────────────────────────────────
//   SHARED_SECRET             matches the Worker's SECRET, checked via
//                             x-8848-secret header
//   WWDR_PEM_B64
//   SIGNER_CERT_PEM_B64
//   SIGNER_KEY_PEM_B64
//   SIGNER_KEY_PASSPHRASE
//   PASS_TYPE_ID              e.g. pass.ma.8848club.membership
//   APPLE_TEAM_ID

const express = require("express");
const { PKPass } = require("passkit-generator");
const path = require("path");

const app = express();
app.use(express.json());

const MODEL_PATH = path.join(__dirname, "models", "membership.pass");

function pemFromB64(b64) {
  if (!b64) return null;
  return Buffer.from(b64, "base64").toString("utf8");
}

app.post("/generate", async (req, res) => {
  const secret = req.headers["x-8848-secret"];
  if (secret !== process.env.SHARED_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { passId, memberName, memberId, planName, expiryDate, unlockUrl } = req.body || {};
  if (!passId || !memberName || !unlockUrl) {
    return res.status(400).json({ error: "Missing passId, memberName or unlockUrl" });
  }

  try {
    const pass = await PKPass.from(
      {
        model: MODEL_PATH,
        certificates: {
          wwdr: pemFromB64(process.env.WWDR_PEM_B64),
          signerCert: pemFromB64(process.env.SIGNER_CERT_PEM_B64),
          signerKey: pemFromB64(process.env.SIGNER_KEY_PEM_B64),
          signerKeyPassphrase: process.env.SIGNER_KEY_PASSPHRASE
        }
      },
      {
        serialNumber: passId,
        passTypeIdentifier: process.env.PASS_TYPE_ID,
        teamIdentifier: process.env.APPLE_TEAM_ID,
        authenticationToken: require("crypto").createHash("sha256").update(passId).digest("hex"),
        description: "8848 Club Membership"
      }
    );

    // Clear and set fields fresh so re-generation (renewals) doesn't
    // duplicate entries from the template
    pass.headerFields.splice(0, pass.headerFields.length);
    pass.primaryFields.splice(0, pass.primaryFields.length);
    pass.secondaryFields.splice(0, pass.secondaryFields.length);

    pass.headerFields.push({ key: "plan", label: "PLAN", value: planName || "Membership" });
    pass.primaryFields.push({ key: "member", label: "MEMBER", value: memberName });
    pass.secondaryFields.push(
      {
        key: "expiry",
        label: "VALID UNTIL",
        value: expiryDate || "",
        dateStyle: "PKDateStyleMedium"
      },
      { key: "memberId", label: "MEMBER ID", value: memberId || "", textAlignment: "PKTextAlignmentRight" }
    );

    pass.setBarcodes({
      message: unlockUrl,
      format: "PKBarcodeFormatQR",
      messageEncoding: "iso-8859-1",
      altText: "Scan to unlock"
    });

    const buffer = pass.getAsBuffer();

    res.set({
      "Content-Type": "application/vnd.apple.pkpass",
      "Content-Disposition": `attachment; filename="8848-${passId}.pkpass"`
    });
    return res.send(buffer);
  } catch (err) {
    console.error("Pass generation error:", err);
    return res.status(500).json({ error: "Pass generation failed", detail: err.message });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`8848 pass-service listening on ${PORT}`));
