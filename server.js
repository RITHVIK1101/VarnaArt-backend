const express = require('express');
const mongoose = require('mongoose');
const productRoutes = require('./routes/ProductRoutes'); // Capital "P"
const authRoutes = require('./routes/authRoutes'); // Import auth routes
const galleryRoutes = require('./routes/galleryRoutes');

const cartRoutes = require('./routes/cartRoutes'); // Import cart routes
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5100;

// Middleware to parse JSON
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Mount routes
app.use('/api/auth', authRoutes); // Auth routes
app.use('/api/products', productRoutes); // Product routes
app.use('/api/gallery', galleryRoutes);
app.use('/api/cart', cartRoutes);


// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
