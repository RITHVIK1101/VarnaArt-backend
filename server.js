// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const xlsx = require('xlsx');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5100;

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://66b7900cb4d6406321245fed--varnaart.netlify.app',
      'https://master--varnaart.netlify.app',
      'https://varnaart.netlify.app'      
    ];
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(helmet());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB:', err));

// Define Schemas

// Updated Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: String, required: true },
  description: { type: String, required: true },
  imageUrls: { type: [String], required: true }, // Changed to array
  length: { type: Number, required: true },
  width: { type: Number, required: true },
  unit: { type: String, required: true },
  types: { type: [String], required: true }, // Array of painting types
  tags: { type: [String], required: true },  // Array of tags
});

// Middleware to set default empty arrays for 'types' and 'tags' if they don't exist
productSchema.pre('save', function(next) {
  if (!this.types) {
    this.types = [];
  }
  if (!this.tags) {
    this.tags = [];
  }
  next();
});

// Gallery Item Schema
const galleryItemSchema = new mongoose.Schema({
  description: { type: String, required: true },
  imageUrls: { type: [String], required: true }, // Changed to array
});

// Middleware to set default empty arrays for 'imageUrls' if they don't exist
galleryItemSchema.pre('save', function(next) {
  if (!this.imageUrls) {
    this.imageUrls = [];
  }
  next();
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true }, // Added uniqueness
  password: { type: String, required: true },
  name: { type: String, required: true },
});

// Cart Product Schema
const cartProductSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, default: 1 },
});

// Inventory Schema
const inventorySchema = new mongoose.Schema({
  fields: Object // Flexible schema that allows any key-value pairs
});

// Models
const Product = mongoose.model('Product', productSchema);
const GalleryItem = mongoose.model('GalleryItem', galleryItemSchema);
const User = mongoose.model('User', userSchema);
const CartProduct = mongoose.model('CartProduct', cartProductSchema);
const Inventory = mongoose.model('Inventory', inventorySchema);

// Password Hashing Middleware
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Setup multer for image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Ensure this directory exists
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
    Length: product.length,
    Width: product.width,
    Unit: product.unit,
    Types: product.types.join(', '),
    Tags: product.tags.join(', '),
    Images: product.imageUrls.join(', '), // Add images as comma-separated string
  }));
  const worksheet = xlsx.utils.json_to_sheet(worksheetData);
  xlsx.utils.book_append_sheet(workbook, worksheet, 'Products');
  xlsx.writeFile(workbook, 'products.xlsx');
};

// POST Routes

// Create a New Product with Multiple Images
app.post('/api/products', upload.array('images', 10), async (req, res) => { // Allow up to 10 images
  const { name, price, description, length, width, unit, types, tags } = req.body;
  const imageUrls = req.files.map(file => `/uploads/${file.filename}`); // Array of image URLs

  // Parse 'types' and 'tags' from JSON strings to arrays
  let parsedTypes = [];
  let parsedTags = [];

  try {
    parsedTypes = types ? JSON.parse(types) : [];
    if (!Array.isArray(parsedTypes)) throw new Error();
  } catch (error) {
    return res.status(400).json({ error: 'Invalid format for types. It should be a JSON array.' });
  }

  try {
    parsedTags = tags ? JSON.parse(tags) : [];
    if (!Array.isArray(parsedTags)) throw new Error();
  } catch (error) {
    return res.status(400).json({ error: 'Invalid format for tags. It should be a JSON array.' });
  }

  // Validate required fields
  if (!name || !price || !description || imageUrls.length === 0 || !length || !width || !unit) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const newProduct = new Product({
    name,
    price,
    description,
    imageUrls,
    length,
    width,
    unit,
    types: parsedTypes,
    tags: parsedTags,
  });

  try {
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (error) {
    res.status(400).json({ error: 'Error saving product. Please check your data.' });
  }
});

// Create a New Gallery Item with Multiple Images
app.post('/api/gallery', upload.array('images', 10), async (req, res) => { // Allow up to 10 images
  const { description } = req.body;
  const imageUrls = req.files.map(file => `/uploads/${file.filename}`); // Array of image URLs

  // Validate required fields
  if (!description || imageUrls.length === 0) {
    return res.status(400).json({ error: 'Description and at least one image are required.' });
  }

  const newGalleryItem = new GalleryItem({ description, imageUrls });

  try {
    await newGalleryItem.save();
    res.status(201).json(newGalleryItem);
  } catch (error) {
    res.status(400).json({ error: 'Error saving gallery item. Please check your data.' });
  }
});

// GET Routes

// Get All Products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    const formattedProducts = products.map(product => ({
      ...product.toObject(),
      types: product.types || [],
      imageUrls: product.imageUrls || [],
    }));
    res.status(200).json(formattedProducts);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching products.' });
  }
});

// Get Single Product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found.' });
    }
    res.status(200).json(product);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching the product.' });
  }
});

// Get All Gallery Items
app.get('/api/gallery', async (req, res) => {
  try {
    const galleryItems = await GalleryItem.find();
    res.status(200).json(galleryItems);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching gallery items.' });
  }
});

// DELETE Routes

// Delete Multiple Products
app.post('/api/products/delete', async (req, res) => {
  try {
    const { ids } = req.body; // Expects an array of product IDs to delete

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'No product IDs provided for deletion.' });
    }

    // Validate that all IDs are valid MongoDB ObjectIds
    const validIds = ids.filter(id => mongoose.Types.ObjectId.isValid(id));
    if (validIds.length !== ids.length) {
      return res.status(400).json({ error: 'One or more invalid product IDs provided.' });
    }

    await Product.deleteMany({ _id: { $in: validIds } });
    await writeToExcel(); // Update Excel file
    res.status(200).json({ message: 'Products deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Error deleting products.' });
  }
});

// Delete Multiple Gallery Items
app.post('/api/gallery/delete', async (req, res) => {
  try {
    const { ids } = req.body; // Expects an array of gallery item IDs to delete

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'No gallery item IDs provided for deletion.' });
    }

    // Validate that all IDs are valid MongoDB ObjectIds
    const validIds = ids.filter(id => mongoose.Types.ObjectId.isValid(id));
    if (validIds.length !== ids.length) {
      return res.status(400).json({ error: 'One or more invalid gallery item IDs provided.' });
    }

    await GalleryItem.deleteMany({ _id: { $in: validIds } });
    res.status(200).json({ message: 'Gallery items deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Error deleting gallery items.' });
  }
});

// Cart API Routes

// Add Product to Cart
app.post('/api/cart/add', async (req, res) => {
  const { productId } = req.body;
  const userId = req.userId;

  try {
    let cartProduct = await CartProduct.findOne({ userId, productId });
    if (cartProduct) {
      cartProduct.quantity += 1;
    } else {
      cartProduct = new CartProduct({ userId, productId });
    }
    await cartProduct.save();
    res.status(201).send(cartProduct);
  } catch (error) {
    res.status(400).send(error);
  }
  // const { productId } = req.body;
  // const userId = req.userId; // Ensure userId is set via authentication middleware

  // if (!userId) {
  //   return res.status(401).json({ error: 'Unauthorized: User not authenticated.' });
  // }

  // try {
  //   let cartProduct = await CartProduct.findOne({ userId, productId });
  //   if (cartProduct) {
  //     cartProduct.quantity += 1;
  //   } else {
  //     cartProduct = new CartProduct({ userId, productId });
  //   }
  //   await cartProduct.save();
  //   res.status(201).json(cartProduct);
  // } catch (error) {
  //   res.status(400).json({ error: 'Error adding product to cart.' });
  // }
});

// Get User's Cart
app.get('/api/cart', async (req, res) => {
  const userId = req.userId; // Ensure userId is set via authentication middleware

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized: User not authenticated.' });
  }

  try {
    const cartProducts = await CartProduct.find({ userId }).populate('productId');
    res.status(200).json(cartProducts);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching cart items.' });
  }
});

// Remove Product from Cart
app.post('/api/cart/remove', async (req, res) => {
  const { productId } = req.body;
  const userId = req.userId; // Ensure userId is set via authentication middleware

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized: User not authenticated.' });
  }

  try {
    await CartProduct.deleteOne({ userId, productId });
    res.status(200).json({ message: 'Product removed from cart.' });
  } catch (error) {
    res.status(500).json({ error: 'Error removing product from cart.' });
  }
});

// Stripe Integration

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Create a Checkout Session
app.post('/api/create-checkout-session', async (req, res) => {
  const { cartItems } = req.body;

  if (!cartItems || !Array.isArray(cartItems)) {
    return res.status(400).json({ error: 'Invalid cart items.' });
  }

  const lineItems = cartItems.map(item => ({
    price_data: {
      currency: 'usd',
      product_data: {
        name: item.productId.name,
        images: [`${process.env.FRONTEND_URL}${item.productId.imageUrls[0]}`], // Use first image
      },
      unit_amount: parseFloat(item.productId.price) * 100, // Convert to cents
    },
    quantity: item.quantity,
  }));

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: lineItems,
      mode: 'payment',
      success_url: `${process.env.FRONTEND_URL}/success`,
      cancel_url: `${process.env.FRONTEND_URL}/cart`,
    });

    res.json({ sessionId: session.id });
  } catch (error) {
    console.error('Error creating Stripe checkout session:', error);
    res.status(500).json({ error: 'Server error while creating checkout session.' });
  }
});

// Inventory API Routes

// Get Inventory
app.get('/api/inventory', async (req, res) => {
  try {
    const inventory = await Inventory.find(); // Fetch inventory from the database
    res.status(200).json(inventory);
  } catch (error) {
    console.error('Error fetching inventory:', error);
    res.status(500).json({ error: 'Error fetching inventory.' });
  }
});

// Update Inventory
app.post('/api/inventory', async (req, res) => {
  try {
    const { inventory } = req.body;
    if (!inventory || !Array.isArray(inventory)) {
      return res.status(400).json({ error: 'Invalid inventory data.' });
    }

    // Save the inventory data as flexible objects
    await Inventory.deleteMany(); // Optional: Clears previous inventory data
    await Inventory.insertMany(inventory); // Save new inventory data

    res.status(200).json({ message: 'Inventory updated successfully.' });
  } catch (error) {
    console.error('Error saving inventory:', error);
    res.status(500).json({ error: 'Error saving inventory.' });
  }
});

// Start the Server
app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
