const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Kayıt Ol
exports.register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ 
      name, 
      email, 
      password: hashedPassword,
      role: role || 'user'
    });
    await newUser.save();

    const mailOptions = {
      from: 'yamanramo2@gmail.com',
      to: email,
      subject: 'Success Register',
      text: `Hello ${name},\n\nYour account has been successfully registered using ${email}!`
    };

    await transporter.sendMail(mailOptions);
    res.status(201).json({ message: "User registered & success email sent!" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Giriş Yap
exports.login = async (req, res) => {
  try {
    const { name, password } = req.body;
    const user = await User.findOne({ name });
    if (!user) return res.status(400).json({ message: "User not found!" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect password!" });

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '1h' }
    );
    res.json({ message: "Login successful!", token, role: user.role }); 
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Şifremi Unuttum
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User with this email not found!" });

    const token = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 saat
    await user.save();

    const resetUrl = `http://localhost:3000/reset-password.html?token=${token}`;
    const mailOptions = {
      from: 'yamanramo2@gmail.com',
      to: email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Click the link below to reset your password:\n\n${resetUrl}\n\nIf you didn't request this, please ignore this email.`
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: "Password reset link sent to your email!" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Yeni Şifreyi Kaydet
exports.resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: "Password reset token is invalid or has expired!" });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: "Password has been successfully updated! You can now log in." });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Admin Paneli - Kullanıcı Listesi
exports.getAdminUsers = async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Tüm Kullanıcıları Sil (Test için)
exports.deleteUsers = async (req, res) => {
  try {
    await User.deleteMany({});
    res.json({ message: "All users deleted successfully!" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// 1. Rol Güncelleme (Kendini engelleme koruması eklendi)
exports.updateUserRole = async (req, res) => {
  try {
    // req.user.id veya req.user._id (token'dan gelen ID) ile parametreden gelen ID'yi karşılaştır
    if (req.user && req.user.id === req.params.id) {
        return res.status(403).json({ message: 'You cannot change your own role!' });
    }

    const { role } = req.body;
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role specified!' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true, select: '-password' }
    );
    
    if (!updatedUser) return res.status(404).json({ message: 'User not found!' });
    res.json({ message: 'Role updated successfully', user: updatedUser });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

// 2. Yeni Kullanıcı Silme Fonksiyonu
exports.deleteUser = async (req, res) => {
  try {
    // Kendi hesabını silmesini engelle
    if (req.user && req.user.id === req.params.id) {
        return res.status(403).json({ message: 'You cannot delete yourself!' });
    }

    const deletedUser = await User.findByIdAndDelete(req.params.id);
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found!' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};