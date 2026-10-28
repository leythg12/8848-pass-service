// server.js — HYBRID Apple Wallet pass service (Render).
//
// Same service as before (passkit-generator, same endpoint, same env vars),
// rebranded from 8848 Club to HYBRID. Nothing to change in Render's settings:
//   SHARED_SECRET            matches the Worker's SECRET (x-8848-secret header)
//   WWDR_PEM_B64
//   SIGNER_CERT_PEM_B64
//   SIGNER_KEY_PEM_B64
//   SIGNER_KEY_PASSPHRASE
//   PASS_TYPE_ID             keep pass.ma.8848club — changing it breaks updates for existing passes
//   APPLE_TEAM_ID            J8A4GVWKC2

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
          signerKeyPassphrase: process.env.SIGNER_KEY_PASSPHRASE,
        },
      },
      {
        serialNumber: passId,
        passTypeIdentifier: process.env.PASS_TYPE_ID,
        teamIdentifier: process.env.APPLE_TEAM_ID,
        authenticationToken: passId.replace(/-/g, ""),
        description: "Pass membre HYBRID",
      },
    );

    // Reset fields so renewals don't duplicate template entries
    for (const f of [pass.headerFields, pass.primaryFields, pass.secondaryFields, pass.backFields]) {
      f.splice(0, f.length);
    }

    pass.headerFields.push({ key: "plan", label: "FORMULE", value: planName || "Abonnement" });
    pass.primaryFields.push({ key: "member", label: "MEMBRE", value: memberName });
    pass.secondaryFields.push(
      {
        key: "expiry",
        label: "VALABLE JUSQU'AU",
        value: expiryDate || "",
        dateStyle: "PKDateStyleMedium",
      },
      { key: "memberId", label: "N° MEMBRE", value: memberId || "", textAlignment: "PKTextAlignmentRight" },
    );
    pass.backFields.push(
      { key: "about", label: "HYBRID", value: "Force, cardio et mobilité réunis en un seul mouvement. Chaque effort compte." },
      { key: "contact", label: "CONTACT", value: "fitness@villasahrai.com\n+212 664 959 648" },
      { key: "web", label: "SITE", value: "https://www.8848club.ma" },
    );

    pass.setBarcodes({
      message: unlockUrl,
      format: "PKBarcodeFormatQR",
      messageEncoding: "iso-8859-1",
      altText: "Scannez pour entrer",
    });

    const buffer = pass.getAsBuffer();
    res.set({
      "Content-Type": "application/vnd.apple.pkpass",
      "Content-Disposition": `attachment; filename="hybrid-${passId}.pkpass"`,
    });
    return res.send(buffer);
  } catch (err) {
    console.error("Pass generation error:", err);
    return res.status(500).json({ error: "Pass generation failed", detail: err.message });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok", brand: "HYBRID" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`HYBRID pass-service listening on ${PORT}`));
