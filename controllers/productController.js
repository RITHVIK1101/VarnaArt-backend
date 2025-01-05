const Product = require('../models/Product');

exports.createProduct = async (req, res) => {
  const {
    name,
    price,
    description,
    length,
    width,
    unit,
    types,
    tags,
    imageUrls, // Expecting an array of Cloudinary URLs
  } = req.body;

  // Validate required fields
  if (
    !name ||
    !price ||
    !description ||
    !length ||
    !width ||
    !unit ||
    !imageUrls ||
    !Array.isArray(imageUrls) ||
    imageUrls.length === 0
  ) {
    return res.status(400).json({ error: 'All fields and at least one image URL are required.' });
  }

  try {
    // Create new product document
    const newProduct = new Product({
      name,
      price,
      description,
      imageUrls, // Cloudinary URLs from the frontend
      length,
      width,
      unit,
      types: types || [],
      tags: tags || [],
    });

    await newProduct.save();

    res.status(201).json({
      message: 'Product created successfully.',
      product: newProduct,
    });
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Other controller functions remain unchanged
exports.getAllProducts = async (req, res) => {
  try {
    const products = await Product.find();
    res.status(200).json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

exports.getProductById = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found.' });
    }
    res.status(200).json(product);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

exports.deleteProducts = async (req, res) => {
  const { ids } = req.body;

  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'No product IDs provided for deletion.' });
  }

  try {
    await Product.deleteMany({ _id: { $in: ids } });
    res.status(200).json({ message: 'Products deleted successfully.' });
  } catch (error) {
    console.error('Error deleting products:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};
