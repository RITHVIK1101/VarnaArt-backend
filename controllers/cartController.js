const Cart = require('../models/CartProduct');
const Product = require('../models/Product');

// Add product to cart
exports.addToCart = async (req, res) => {
  const { userId, productId, quantity } = req.body;

  if (!userId || !productId || !quantity || quantity <= 0) {
    return res.status(400).json({ error: 'Valid userId, productId, and quantity are required.' });
  }

  try {
    // Check if the cart exists for the user
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      // If no cart exists, create a new one
      cart = new Cart({
        userId,
        products: [{ productId, quantity }],
      });
    } else {
      // If cart exists, check if the product is already in the cart
      const productIndex = cart.products.findIndex(p => p.productId.toString() === productId);

      if (productIndex > -1) {
        // If product exists, update the quantity
        cart.products[productIndex].quantity += quantity;
      } else {
        // If product does not exist, add it to the cart
        cart.products.push({ productId, quantity });
      }
    }

    await cart.save();
    res.status(200).json({ message: 'Product added to cart successfully.', cart });
  } catch (error) {
    console.error('Error adding to cart:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Get user cart
exports.getCart = async (req, res) => {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  try {
    const cart = await Cart.findOne({ userId }).populate('products.productId');
    if (!cart) {
      return res.status(404).json({ error: 'Cart not found.' });
    }
    res.status(200).json(cart);
  } catch (error) {
    console.error('Error fetching cart:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Remove product from cart
exports.removeFromCart = async (req, res) => {
  const { userId, productId } = req.body;

  if (!userId || !productId) {
    return res.status(400).json({ error: 'Valid userId and productId are required.' });
  }

  try {
    const cart = await Cart.findOne({ userId });
    if (!cart) {
      return res.status(404).json({ error: 'Cart not found.' });
    }

    // Filter out the product to remove
    cart.products = cart.products.filter(p => p.productId.toString() !== productId);

    await cart.save();
    res.status(200).json({ message: 'Product removed from cart.', cart });
  } catch (error) {
    console.error('Error removing product from cart:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Clear user cart
exports.clearCart = async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  try {
    const cart = await Cart.findOneAndDelete({ userId });
    if (!cart) {
      return res.status(404).json({ error: 'Cart not found.' });
    }
    res.status(200).json({ message: 'Cart cleared successfully.' });
  } catch (error) {
    console.error('Error clearing cart:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};
