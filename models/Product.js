const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  price: {
    type: String, // Consider changing to Number for numeric operations
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  imageUrls: {
    type: [String], // Array of image URLs
    required: true,
  },
  length: {
    type: Number,
    required: true,
  },
  width: {
    type: Number,
    required: true,
  },
  unit: {
    type: String,
    required: true,
    enum: ['cm', 'inches', 'feet', 'meters'],
  },
  types: {
    type: [String], // Array of product types
    required: true,
    default: [],
  },
  tags: {
    type: [String], // Array of product tags
    required: true,
    default: [],
  },
}, { timestamps: true });

module.exports = mongoose.model('Product', productSchema);
