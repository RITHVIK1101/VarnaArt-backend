// routes/productRoutes.js
const express = require('express');
const { createProduct, getAllProducts, getProductById, deleteProducts } = require('../controllers/productController');

const router = express.Router();

// Routes without Multer
router.post('/', createProduct); 
router.get('/', getAllProducts);
router.get('/:id', getProductById);
router.post('/delete', deleteProducts);

module.exports = router;
