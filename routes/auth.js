const express = require('express');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const router = express.Router(); 
const jwt = require('jsonwebtoken');

router.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate MFA secret
    const mfaSecret = speakeasy.generateSecret({ name: `Finmark (${email})` });

    const user = new User({
      email,
      password: hashedPassword,
      mfa: {
        enabled: false,
        secret: mfaSecret.base32,
      },
    });

    await user.save();

    //  Generate QR code for Google Authenticator
    const qrCodeDataURL = await qrcode.toDataURL(mfaSecret.otpauth_url);

    // Send QR to frontend
    res.status(201).json({
      message: 'User registered. Scan QR with Google Authenticator.',
      qrCode: qrCodeDataURL,
      email: user.email,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});



router.post('/setup-mfa', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send("User not found");

  const secret = speakeasy.generateSecret({ name: `PlatTech (${email})` });
  user.totpSecret = secret.base32;
  await user.save();

  qrcode.toDataURL(secret.otpauth_url, (err, imageUrl) => {
    if (err) return res.status(500).send("QR generation failed");
    res.json({ qr: imageUrl, secret: secret.base32 });
  });
});

router.post('/verify-mfa-setup', async (req, res) => {
  const { email, token } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send("User not found");

  const isValid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!isValid) return res.status(401).send("Invalid token");
  user.isMfaEnabled = true;
  await user.save();
  res.send("MFA setup complete");
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    if (user.mfa && user.mfa.secret) {
      // Store user email temporarily in session or send back MFA challenge
      return res.status(200).json({ message: 'MFA required' });
    }

    const token = jwt.sign(
  { userId: user._id, email: user.email },
  process.env.JWT_SECRET,
  { expiresIn: '1h' }
);

    res.status(200).json({ message: 'Login successful', token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

router.post('/verify-mfa', async (req, res) => {
  const { email, token } = req.body;

  const user = await User.findOne({ email });
  if (!user || !user.mfa || !user.mfa.secret) {
    return res.status(400).json({ message: 'MFA not setup for this user' });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfa.secret,
    encoding: 'base32',
    token
  });

  if (!verified) {
    return res.status(401).json({ message: 'Invalid MFA token' });
  }

  const jwtToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: '1h'
  });

  res.status(200).json({ message: 'MFA verified', token: jwtToken });
});

router.post('/verify-mfa-register', async (req, res) => {
  const { email, token } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token
  });

  if (verified) {
    const jwtToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token: jwtToken });
  } else {
    res.status(400).json({ message: 'Invalid MFA code' });
  }
});

router.post('/verify-mfa-login', async (req, res) => {
  const { email, token } = req.body;

  const user = await User.findOne({ email });
  if (!user || !user.mfaEnabled || !user.mfaSecret) {
    return res.status(400).json({ message: 'MFA not set up for this user' });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token
  });

  if (!verified) {
    return res.status(401).json({ message: 'Invalid MFA code' });
  }

  const payload = { userId: user._id, email: user.email };
  const tokenJWT = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '1h'
  });

  res.json({
    message: 'Login successful with MFA',
    token: tokenJWT
  });
});

const authMiddleware = require('../middleware/auth');

router.get('/dashboard', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 🔥 FIX: Fetch full user from DB
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({
      message: `Welcome back, ${user.fullName || user.username || user.email}! 🎉`,
      user: {
        id: user._id,
        email: user.email,
        fullName: user.fullName,
        username: user.username,
        role: user.role
      }
    });

  } catch (err) {
    console.error(err);
    res.status(401).json({ message: 'Token invalid or expired' });
  }
});


router.post('/verify-mfa', async (req, res) => {
  const { email, token } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !user.mfa?.secret) return res.status(400).json({ message: 'User or MFA not found' });

    const verified = speakeasy.totp.verify({
      secret: user.mfa.secret,
      encoding: 'base32',
      token,
    });

    if (verified) {
      user.mfa.enabled = true;
      await user.save();

      // Generate JWT token or success message
      const jwtToken = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

      return res.status(200).json({ message: 'MFA verified', token: jwtToken });
    } else {
      return res.status(400).json({ message: 'Invalid MFA token' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Generate QR code for MFA
router.get('/generate-mfa-qr', async (req, res) => {
  const { email, secret } = req.query;

  if (!email || !secret) {
    return res.status(400).json({ message: 'Email and secret are required' });
  }

  // Construct the otpauth URL
  const otpAuthUrl = `otpauth://totp/${encodeURIComponent('FinmarkWeb')} (${encodeURIComponent(email)})?secret=${secret}&issuer=FinmarkWeb`;

  try {
    // Generate QR code as a data URL
    const qrCodeDataURL = await qrcode.toDataURL(otpAuthUrl);
    res.json({ qrCodeDataURL });
  } catch (err) {
    res.status(500).json({ message: 'Failed to generate QR code', error: err.message });
  }
});

router.get('/users', async (req, res) => {
  try {
    const users = await User.find({}, '-password -__v'); // exclude sensitive fields
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Server error retrieving users' });
  }
});


module.exports = router;
