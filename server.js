const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const xlsx = require('xlsx');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 8080;

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  optionsSuccessStatus: 200,
};


app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Could not connect to MongoDB:', err));

const productSchema = new mongoose.Schema({
  name: String,
  price: String,
  description: String,
  imageUrl: String,
});

const galleryItemSchema = new mongoose.Schema({
  description: String,
  imageUrl: String,
});

const Product = mongoose.model('Product', productSchema);
const GalleryItem = mongoose.model('GalleryItem', galleryItemSchema);

// Setup multer for image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

// Function to write data to Excel file
const writeToExcel = async () => {
  const products = await Product.find();
  const workbook = xlsx.utils.book_new();
  const worksheetData = products.map(product => ({
    Name: product.name,
    Price: product.price,
    Description: product.description,
  }));
  const worksheet = xlsx.utils.json_to_sheet(worksheetData);
  xlsx.utils.book_append_sheet(workbook, worksheet, 'Products');
  xlsx.writeFile(workbook, 'products.xlsx');
};

// POST Routes
app.post('/api/products', upload.single('image'), async (req, res) => {
  const { name, price, description } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

  const newProduct = new Product({ name, price, description, imageUrl });
  try {
    await newProduct.save();
    await writeToExcel(); // Update Excel file
    res.status(201).send(newProduct);
  } catch (error) {
    res.status(400).send(error);
  }
});

app.post('/api/gallery', upload.single('image'), async (req, res) => {
  const { description } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

  const newGalleryItem = new GalleryItem({ description, imageUrl });
  try {
    await newGalleryItem.save();
    res.status(201).send(newGalleryItem);
  } catch (error) {
    res.status(400).send(error);
  }
});

// GET Routes
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.status(200).send(products);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).send('Product not found');
    }
    res.status(200).send(product);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get('/api/gallery', async (req, res) => {
  try {
    const galleryItems = await GalleryItem.find();
    res.status(200).send(galleryItems);
  } catch (error) {
    res.status(500).send(error);
  }
});

// DELETE Routes
app.post('/api/products/delete', async (req, res) => {
  try {
    const { ids } = req.body; // Expects an array of product IDs to delete
    await Product.deleteMany({ _id: { $in: ids } });
    await writeToExcel(); // Update Excel file
    res.status(200).send({ message: 'Products deleted' });
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post('/api/gallery/delete', async (req, res) => {
  try {
    const { ids } = req.body; // Expecting an array of IDs to delete
    if (!ids || ids.length === 0) {
      return res.status(400).send('No gallery items selected for deletion.');
    }

    await GalleryItem.deleteMany({ _id: { $in: ids } });
    res.status(200).send('Gallery items deleted successfully.');
  } catch (error) {
    res.status(500).send('Error deleting gallery items.');
  }
});



app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
