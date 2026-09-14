const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

const verifyAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Access denied. No token provided." });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: "Access forbidden. Admins only." });
    }
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).json({ message: "Invalid token." });
  }
};

module.exports = verifyAdmin;