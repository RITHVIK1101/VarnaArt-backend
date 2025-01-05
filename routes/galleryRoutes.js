const express = require('express');
const { addGalleryItem, getAllGalleryItems, getGalleryItemById, deleteGalleryItems } = require('../controllers/galleryController');

const router = express.Router();

// Routes
router.post('/', addGalleryItem); // Add a new gallery item
router.get('/', getAllGalleryItems); // Get all gallery items
router.get('/:id', getGalleryItemById); // Get a gallery item by ID
router.post('/delete', deleteGalleryItems); // Delete multiple gallery items

module.exports = router;
