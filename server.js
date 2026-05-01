const jwt = require('jsonwebtoken');
const SECRET = "mysecretkey";
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();

// ✅ Middlewares FIRST
app.use(cors());        // MUST be here
app.use(express.json());

// 🔹 MySQL Connection
const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});

db.connect((err) => {
  if (err) {
    console.error("DB connection failed:", err);
  } else {
    console.log("Connected to MySQL");
  }
});

function verifyToken(req, res, next) {

    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send("No token provided");
    }

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send("Invalid token");
        }

        req.user = decoded; // store user info
        next(); // go to next step
    });
}

app.get('/dashboard', verifyToken, (req, res) => {

    res.json({
        message: "Welcome to dashboard",
        user: req.user
    });

});

function verifyAdmin(req, res, next) {

    if (req.user.role !== "admin") {
        return res.status(403).send("Access denied: Admin only");
    }

    next();
}

app.get('/admin-data', verifyToken, verifyAdmin, (req, res) => {

    res.json({
        message: "This is admin-only data",
        user: req.user
    });

});

// 🔹 Test API
app.get('/', (req, res) => {
    res.send("API is working!");
});

// 🔹 REGISTER API
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [username, hashedPassword, role],
        (err, result) => {
            if (err) {
                console.log(err);   // 👈 important for debugging
                return res.status(500).send("Database error");
            }
            res.send("User registered successfully");
        }
    );
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});

app.post('/login', (req, res) => {

    const { username, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, results) => {

            if (err) {
                return res.status(500).send("Database error");
            }

            if (results.length === 0) {
                return res.status(401).send("User not found");
            }

            const user = results[0];

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(401).send("Wrong password");
            }

            // 🔐 Create token
            const token = jwt.sign(
                { id: user.id, role: user.role },
                SECRET,
                { expiresIn: "1h" }
            );

            res.json({ token });
        }
    );
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

app.use(cors({
  origin: "*"
}));