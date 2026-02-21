import express from "express";
import Razorpay from "razorpay";
import crypto from "crypto";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";

dotenv.config();

const app = express();

// IMPORTANT: raw body for webhook verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(cors());

/* =========================
   FIREBASE INITIALIZATION
========================= */

if (!process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
  console.error("Missing FIREBASE_SERVICE_ACCOUNT_BASE64");
  process.exit(1);
}

const serviceAccount = JSON.parse(
  Buffer.from(
    process.env.FIREBASE_SERVICE_ACCOUNT_BASE64,
    "base64"
  ).toString("utf8")
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DB_URL
});

const db = admin.database();

/* =========================
   RAZORPAY INITIALIZATION
========================= */

if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.error("Missing Razorpay credentials");
  process.exit(1);
}

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

/* =========================
   CREATE SUBSCRIPTION
========================= */

app.post("/create-subscription", async (req, res) => {
  try {
    const subscription = await razorpay.subscriptions.create({
      plan_id: process.env.RAZORPAY_PLAN_ID,
      total_count: 12,
      customer_notify: 1
    });

    res.json({ id: subscription.id });

  } catch (err) {
    console.error("Subscription Error:", err);
    res.status(500).json({ error: "Subscription creation failed" });
  }
});

/* =========================
   WEBHOOK HANDLER
========================= */

app.post("/webhook", async (req, res) => {
  try {
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    const signature = req.headers["x-razorpay-signature"];

    const expectedSignature = crypto
      .createHmac("sha256", webhookSecret)
      .update(req.rawBody)
      .digest("hex");

    if (signature !== expectedSignature) {
      return res.status(400).json({ error: "Invalid signature" });
    }

    const event = req.body.event;

    if (event === "subscription.activated") {
      const subscription = req.body.payload.subscription.entity;

      const email = subscription.customer_email;
      const expiryDate = subscription.current_end * 1000;

      const safeEmail = email.replace(/\./g, "_");

      await db.ref("users/" + safeEmail).set({
        active: true,
        expiryDate: expiryDate,
        deviceId: null
      });
    }

    if (
      event === "subscription.cancelled" ||
      event === "subscription.halted"
    ) {
      const subscription = req.body.payload.subscription.entity;
      const email = subscription.customer_email;
      const safeEmail = email.replace(/\./g, "_");

      await db.ref("users/" + safeEmail).update({
        active: false
      });
    }

    res.json({ status: "ok" });

  } catch (err) {
    console.error("Webhook Error:", err);
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

/* =========================
   DEVICE BINDING
========================= */

app.post("/bind-device", async (req, res) => {
  try {
    const { email, deviceId } = req.body;

    if (!email || !deviceId) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const safeEmail = email.replace(/\./g, "_");

    const snapshot = await db.ref("users/" + safeEmail).once("value");
    const user = snapshot.val();

    if (!user || !user.active) {
      return res.status(403).json({ error: "No active subscription" });
    }

    if (user.deviceId && user.deviceId !== deviceId) {
      return res.status(403).json({ error: "Device already bound" });
    }

    await db.ref("users/" + safeEmail).update({
      deviceId: deviceId
    });

    res.json({ success: true });

  } catch (err) {
    console.error("Bind Device Error:", err);
    res.status(500).json({ error: "Device binding failed" });
  }
});

/* =========================
   HEALTH CHECK
========================= */

app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});