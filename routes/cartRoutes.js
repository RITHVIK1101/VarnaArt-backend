const express = require('express');
const { addToCart, getCart, removeFromCart, clearCart } = require('../controllers/cartController');

const router = express.Router();

// Add product to cart
router.post('/add', addToCart);

// Get user's cart
router.get('/:userId', getCart);

// Remove a product from cart
router.post('/remove', removeFromCart);

// Clear the cart
router.post('/clear', clearCart);

module.exports = router;
