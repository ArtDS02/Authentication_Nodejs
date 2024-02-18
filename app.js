// Import các module và thư viện cần thiết
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express(); // Tạo một ứng dụng Express

// Kết nối với cơ sở dữ liệu MongoDB
mongoose.connect('mongodb://localhost:27017/auth_demo')
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err.message);
    });

// Mô hình người dùng trong cơ sở dữ liệu
const User = mongoose.model('User', {
    username: String,
    password: String
});

app.use(bodyParser.json()); // Sử dụng body-parser để phân tích nội dung của yêu cầu HTTP

// Endpoint để đăng ký tài khoản mới
app.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save(); // Lưu thông tin người dùng mới vào cơ sở dữ liệu
        res.status(201).send('User created successfully'); // Trả về thông báo khi đăng ký thành công
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error'); // Trả về lỗi nếu có lỗi xảy ra
    }
});

// Endpoint để đăng nhập
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).send('User not found'); // Trả về lỗi nếu người dùng không tồn tại
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).send('Invalid password'); // Trả về lỗi nếu mật khẩu không chính xác
        }
        const token = jwt.sign({ username: user.username }, 'secret_key'); // Tạo token JWT cho người dùng
        res.status(200).json({ token }); // Trả về token cho người dùng
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error'); // Trả về lỗi nếu có lỗi xảy ra
    }
});

// Middleware xác thực token
function authenticateToken(req, res, next) {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).send('Access denied. No token provided.'); // Trả về lỗi nếu không có token
    }

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) {
            return res.status(403).send('Invalid token'); // Trả về lỗi nếu token không hợp lệ
        }
        req.user = user; // Lưu thông tin người dùng từ token vào request
        next(); // Tiếp tục xử lý tiếp theo
    });
}

// Endpoint bảo vệ, chỉ được truy cập nếu có token hợp lệ
app.get('/protected', authenticateToken, (req, res) => {
    res.send('Welcome to the protected route'); // Trả về thông báo chào mừng nếu token hợp lệ
});

// Chạy server trên cổng 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
