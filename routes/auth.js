const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const authController = require('../controllers/authController');
const verifyAdmin = require('../middlewares/verifyAdmin');

// Doğrulama Hatalarını Yakalayan Ara Katman (Middleware)
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: errors.array()[0].msg });
  }
  next();
};

// Kayıt Ol - Kurallı
router.post('/register', [
  body('name').notEmpty().withMessage('Name cannot be empty!'),
  body('email').isEmail().withMessage('Please enter a valid email address!'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long!')
], validate, authController.register);

// Giriş Yap - Kurallı
router.post('/login', [
  body('name').notEmpty().withMessage('Username is required!'),
  body('password').notEmpty().withMessage('Password is required!')
], validate, authController.login);

// Diğer Rotalar
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// Admin İşlemleri
router.get('/admin/users', verifyAdmin, authController.getAdminUsers);
router.get('/users', authController.getAdminUsers);
router.delete('/users', authController.deleteUsers);

module.exports = router;

router.put('/users/:id/role', verifyAdmin, authController.updateUserRole);
router.delete('/users/:id', verifyAdmin, authController.deleteUser);