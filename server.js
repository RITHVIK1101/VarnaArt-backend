const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const xlsx = require('xlsx');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 8080;

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://66b7900cb4d6406321245fed--varnaart.netlify.app',
      'https://master--varnaart.netlify.app'
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

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
});

const cartProductSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  quantity: { type: Number, default: 1 },
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const Product = mongoose.model('Product', productSchema);
const GalleryItem = mongoose.model('GalleryItem', galleryItemSchema);
const User = mongoose.model('User', userSchema);
const CartProduct = mongoose.model('CartProduct', cartProductSchema);

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

// User Authentication
app.post('/signup', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email in use' });
    }

    const newUser = new User({
      email,
      password,
      name: `${firstName} ${lastName}`,
    });

    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).send('Server error');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET || 'your_jwt_secret_key',
        { expiresIn: '1h' }
      );
      res.status(200).json({ message: 'Login successful', token });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).send('Server error');
  }
});


// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied, token missing' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.userId = user.userId; // Store userId in request
    next();
  });
};
app.get('/UserProtectedRoutes', authenticateToken, (req, res) => {
  res.status(200).json({ user: req.userId, message: 'User is authenticated' });
});
// Cart API routes
app.post('/api/cart/add', authenticateToken, async (req, res) => {
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
});

app.get('/api/cart', authenticateToken, async (req, res) => {
  const userId = req.userId;

  try {
    const cartProducts = await CartProduct.find({ userId }).populate('productId');
    res.status(200).send(cartProducts);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post('/api/cart/remove', authenticateToken, async (req, res) => {
  const { productId } = req.body;
  const userId = req.userId;

  try {
    await CartProduct.deleteOne({ userId, productId });
    res.status(200).send({ message: 'Product removed from cart' });
  } catch (error) {
    res.status(500).send(error);
  }
});
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Create a Checkout Session
app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
  const { cartItems } = req.body;

  const lineItems = cartItems.map(item => ({
    price_data: {
      currency: 'usd',
      product_data: {
        name: item.productId.name,
        images: [item.productId.imageUrl],
      },
      unit_amount: item.productId.price * 100,
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
    res.status(500).send('Server error');
  }
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
