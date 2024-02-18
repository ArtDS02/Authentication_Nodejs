// app.js

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Kết nối với MongoDB
mongoose.connect('mongodb://localhost:27017/auth_demo')
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err.message);
    });


// Mô hình người dùng
const User = mongoose.model('User', {
    username: String,
    password: String
});

app.use(bodyParser.json());

// Đăng ký tài khoản
app.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).send('User created successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Đăng nhập
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).send('User not found');
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).send('Invalid password');
        }
        const token = jwt.sign({ username: user.username }, 'secret_key');
        res.status(200).json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Middleware xác thực
function authenticateToken(req, res, next) {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).send('Access denied. No token provided.');
    }

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) {
            return res.status(403).send('Invalid token');
        }
        req.user = user;
        next();
    });
}

// Route bảo vệ
app.get('/protected', authenticateToken, (req, res) => {
    res.send('Welcome to the protected route');
});

// Chạy server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
