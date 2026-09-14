require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');

const app = express();
const port = process.env.PORT || 3000;
const mongoURI = process.env.MONGO_URI;

app.use(express.json());
app.use(express.static('public'));


mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB Atlas bağlantısı başarıyla kuruldu!'))
  .catch((err) => console.error('Bağlantı hatası:', err));

// Tüm API rotalarını sisteme dahil ediyoruz
app.use('/', authRoutes);

app.listen(port, () => {
  console.log(`Server is up and running at http://localhost:${port}!`);
});