const User = require('../models/User'); // Import the User model
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library'); // Import Google's OAuth2 Client

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID); // Initialize Google OAuth Client

// Sign Up User
exports.signup = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered.' });
    }

    const newUser = new User({ name, email, password }); // just pass the raw password
    await newUser.save(); // The pre-save hook will hash the password

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.status(201).json({
      message: 'User registered successfully.',
      token,
      user: { id: newUser._id, name: newUser.name, email: newUser.email },
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Login User
exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found for email:', email);
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    console.log('Stored hashed password:', user.password);
    console.log('Provided password:', password);

    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Password match result:', isMatch);

    if (!isMatch) {
      console.log('Password mismatch for user:', email);
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.status(200).json({
      message: 'Login successful.',
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};

// Google Login
exports.googleLogin = async (req, res) => {
  const { token } = req.body; // Receive Google ID token from the frontend

  try {
    // Verify the Google ID token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const { name, email } = ticket.getPayload(); // Extract user information

    // Check if the user exists in the database
    let user = await User.findOne({ email });
    if (!user) {
      // If not, create a new user
      user = new User({
        name,
        email,
        password: null, // Password is not required for Google login
      });
      await user.save();
    }

    // Generate a JWT for your app
    const appToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(200).json({
      message: 'Login successful',
      token: appToken,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error('Error during Google login:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
};
