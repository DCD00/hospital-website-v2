// ========================== [1] IMPORT ==========================
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const dotenv = require("dotenv");
const path = require("path");

// ========================== [2] CONFIG ==========================
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ========================== [3] DB Connection ==========================
const db = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

// ========================== [4] ENCRYPTION UTILS ==========================
const secretKey = Buffer.from(process.env.AES_KEY, "hex");
const iv = Buffer.from(process.env.AES_IV, "hex");
const algorithm = "aes-256-cbc";

function encrypt(text) {
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

function decrypt(encryptedData) {
  const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ========================== [5] ROUTES ==========================
app.post("/register", async (req, res) => {
  try {
    const {
      name, idNumber, birthplace, gender, address, phoneNumber,
      email, mrn, maritalStatus, religion, insuranceInfo, insurancePolicyNumber,
      username, password
    } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      `INSERT INTO users (name, idNumber, birthplace, gender, address, phoneNumber,
        email, mrn, maritalStatus, religion, insuranceInfo, insurancePolicyNumber,
        username, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        encrypt(name), encrypt(idNumber), encrypt(birthplace), encrypt(gender),
        encrypt(address), encrypt(phoneNumber), encrypt(email), encrypt(mrn),
        encrypt(maritalStatus), encrypt(religion), encrypt(insuranceInfo),
        encrypt(insurancePolicyNumber), username, hashedPassword
      ]
    );

    res.json({ status: "ok", message: "User registered" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error registering user." });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
  const user = rows[0];

  if (!user) return res.status(400).json({ message: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

  const decryptedData = {
    name: decrypt(user.name),
    idNumber: decrypt(user.idNumber),
    birthplace: decrypt(user.birthplace),
    gender: decrypt(user.gender),
    address: decrypt(user.address),
    phoneNumber: decrypt(user.phoneNumber),
    email: decrypt(user.email),
    mrn: decrypt(user.mrn),
    maritalStatus: decrypt(user.maritalStatus),
    religion: decrypt(user.religion),
    insuranceInfo: decrypt(user.insuranceInfo),
    insurancePolicyNumber: decrypt(user.insurancePolicyNumber),
    username: user.username,
    isDoctor: user.isDoctor
  };

  res.json({ status: "ok", isDoctor: user.isDoctor, data: decryptedData });
});

// ========================== [6] STATIC & START ==========================
app.use(express.static(path.join(__dirname, "../frontend")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

app.listen(5001, '0.0.0.0', () => console.log("MySQL-based server running on port 5001"));
