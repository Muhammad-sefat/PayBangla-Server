// index.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const client = new MongoClient(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

let usersCollection, transactionsCollection;

client.connect((err) => {
  if (err) throw err;
  const db = client.db("mfs");
  usersCollection = db.collection("users");
  transactionsCollection = db.collection("transactions");
  console.log("Connected to MongoDB");
});

app.use(cors());
app.use(express.json());

const authMiddleware = (req, res, next) => {
  const token = req.header("x-auth-token");
  if (!token)
    return res.status(401).json({ msg: "No token, authorization denied" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ msg: "Access denied" });
  next();
};

// Register User or Agent
app.post("/api/register", async (req, res) => {
  const { name, mobileNumber, email, pin, role } = req.body;

  if (!name || !mobileNumber || !email || !pin || !role) {
    return res.status(400).json({ msg: "Please enter all fields" });
  }

  try {
    let user = await usersCollection.findOne({
      $or: [{ mobileNumber }, { email }],
    });
    if (user) {
      return res.status(400).json({ msg: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPin = await bcrypt.hash(pin, salt);

    user = {
      name,
      mobileNumber,
      email,
      pin: hashedPin,
      status: "pending",
      balance: role === "agent" ? 10000 : 0,
      role,
    };

    await usersCollection.insertOne(user);
    res.status(201).json({ msg: "User registered, pending admin approval" });
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Login

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
