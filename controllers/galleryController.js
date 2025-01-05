const Gallery = require('../models/GalleryItem');

// Add a new gallery item
exports.addGalleryItem = async (req, res) => {
    const { description, imageUrls, type, tags } = req.body;
  
    // Validate required fields
    if (
      !description ||
      !imageUrls ||
      !Array.isArray(imageUrls) ||
      imageUrls.length === 0 ||
      !type ||
      !tags ||
      !Array.isArray(tags) ||
      tags.length === 0
    ) {
      return res.status(400).json({ error: 'Description, type, tags, and at least one image URL are required.' });
    }
  
    try {
      // Create a new gallery item
      const newGalleryItem = new Gallery({
        description,
        imageUrls,
        type,
        tags,
      });
  
      await newGalleryItem.save();
  
      res.status(201).json({
        message: 'Gallery item added successfully.',
        galleryItem: newGalleryItem,
      });
    } catch (error) {
      console.error('Error adding gallery item:', error);
      res.status(500).json({ error: 'Internal server error.' });
    }
  };
  
// Get all gallery items
exports.getAllGalleryItems = async (req, res) => {
  try {
    const galleryItems = await Gallery.find();
    res.status(200).json(galleryItems);
  } catch (error) {
    console.error('Error fetching gallery items:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Get a single gallery item by ID
exports.getGalleryItemById = async (req, res) => {
  try {
    const galleryItem = await Gallery.findById(req.params.id);
    if (!galleryItem) {
      return res.status(404).json({ error: 'Gallery item not found.' });
    }
    res.status(200).json(galleryItem);
  } catch (error) {
    console.error('Error fetching gallery item:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Delete multiple gallery items
exports.deleteGalleryItems = async (req, res) => {
  const { ids } = req.body;

  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'No gallery item IDs provided for deletion.' });
  }

  try {
    await Gallery.deleteMany({ _id: { $in: ids } });
    res.status(200).json({ message: 'Gallery items deleted successfully.' });
  } catch (error) {
    console.error('Error deleting gallery items:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};
