const express = require('express');
const { signup, login } = require('../controllers/authControllers'); // Import the auth controllers
const router = express.Router();

// Use the controller methods for routes
router.post('/signup', signup); // Signup route
router.post('/login', login);   // Login route
router.post('/google-login', googleLogin);


module.exports = router; // Export the router once
