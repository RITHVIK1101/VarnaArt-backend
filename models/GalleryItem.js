const mongoose = require('mongoose');

const gallerySchema = new mongoose.Schema({
  description: {
    type: String,
    required: true,
  },
  imageUrls: {
    type: [String], // Array of image URLs
    required: true,
  },
  type: {
    type: String, // e.g., "Abstract", "Modern"
    required: true,
  },
  tags: {
    type: [String], // e.g., ["art", "canvas", "acrylic"]
    required: true,
    default: [], // Ensure it's an empty array if not provided
  },
}, { timestamps: true });

module.exports = mongoose.model('Gallery', gallerySchema);
