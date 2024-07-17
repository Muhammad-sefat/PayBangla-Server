// index.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require("mongodb");
const dotenv = require("dotenv");
const app = express();
const PORT = process.env.PORT || 5000;

dotenv.config();

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

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.dbn21dt.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    const database = client.db("payBangla");
    const usersCollection = database.collection("user");

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
          balance: role === "agent" ? 10000 : 40,
          role,
        };

        await usersCollection.insertOne(user);
        res
          .status(201)
          .json({ msg: "User registered, pending admin approval" });
      } catch (err) {
        res.status(500).send("Server error");
      }
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

// Login

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
