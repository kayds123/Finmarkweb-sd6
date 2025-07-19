const express = require('express');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const saltRounds = 10;
require('dotenv').config();
const mongoose = require('mongoose'); // ✅ Only once

// Use the mock Kafka client for development
const { Kafka } = require('./kafka-mock');
// In production, you would use the real kafkajs client:
// const { Kafka } = require('kafkajs');


const USERS_FILE = path.join(__dirname, 'users.json');
const authRoutes = require('./routes/auth'); // ✅ correct
const app = express();
app.use(bodyParser.json()); // ✅ required to parse JSON

// ✅ this must match your Postman URL path
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;


// Initialize Kafka client
const kafka = new Kafka({
    clientId: 'finmark-web-app',
    brokers: ['localhost:9092'] // This will be ignored by the mock
});

// Create a producer instance
const producer = kafka.producer();

// Create a consumer instance
const consumer = kafka.consumer({ groupId: 'finmark-web-consumer' });

// Connect to Kafka and set up consumer
async function setupKafka() {
    await producer.connect();
    
    await consumer.connect();
    await consumer.subscribe({ topic: 'user-actions', fromBeginning: true });
    
    await consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
            try {
                // Extract the message value
                let messageValue;
                if (typeof message.value === 'string') {
                    try {
                        messageValue = JSON.parse(message.value);
                    } catch (e) {
                        messageValue = message.value;
                    }
                } else if (message.value && typeof message.value === 'object') {
                    // If value is an object, it might be from our mock
                    messageValue = message.value.value ? 
                        (typeof message.value.value === 'string' ? JSON.parse(message.value.value) : message.value.value) :
                        message.value;
                }
                
                // If we have a string that looks like JSON, try to parse it
                if (typeof messageValue === 'string' && (messageValue.startsWith('{') || messageValue.startsWith('['))) {
                    try {
                        messageValue = JSON.parse(messageValue);
                    } catch (e) {
                        // If parsing fails, keep the string as is
                    }
                }

                // Log the message details
                const logDetails = {
                    topic,
                    partition,
                    key: message.key ? (typeof message.key === 'string' ? message.key : message.key.toString()) : null,
                    timestamp: message.timestamp || new Date().toISOString()
                };

                // If we have a parsed object with an action, log it
                if (messageValue && typeof messageValue === 'object') {
                    logDetails.action = messageValue.action || 'no-action';
                    
                    // Handle specific actions
                    if (messageValue.action) {
                        switch (messageValue.action) {
                            case 'user.login':
                                console.log('User login detected:', {
                                    userId: messageValue.userId || 'unknown',
                                    username: messageValue.username || 'unknown',
                                    timestamp: messageValue.timestamp || logDetails.timestamp
                                });
                                break;
                                
                            case 'user.logout':
                                console.log('User logout detected:', {
                                    userId: messageValue.userId || 'unknown',
                                    username: messageValue.username || 'unknown',
                                    timestamp: messageValue.timestamp || logDetails.timestamp
                                });
                                break;
                                
                            case 'test.message':
                                console.log('Test message received:', messageValue.message || 'No message');
                                break;
                                
                            default:
                                console.log('Received message with action:', messageValue.action);
                        }
                    } else {
                        console.log('Received message:', messageValue);
                    }
                } else {
                    console.log('Received raw message:', messageValue);
                }
                
                console.log('Message details:', logDetails);
                
            } catch (error) {
                console.error('Error processing Kafka message:', error);
                console.error('Message that caused the error:', {
                    value: message.value,
                    key: message.key,
                    headers: message.headers,
                    topic,
                    partition
                });
            }
        },
    });
    
    console.log('Kafka consumer is running');
}

// Call the setup function
setupKafka().catch(console.error);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'finmark_secret_key',
    resave: false,
    saveUninitialized: true
}));

// Load users from file
function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = fs.readFileSync(USERS_FILE, 'utf8');
            return JSON.parse(data);
        }
        console.log('No users file found, using default users');
        return [];
    } catch (err) {
        console.error('Error loading users:', err);
        return [];
    }
}

// Initialize users array
let USERS = loadUsers();

// Save users to file
function saveUsers(users) {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    } catch (err) {
        console.error('Error saving users:', err);
    }
}

// Update the demo users to use hashed passwords
async function updateExistingUsers() {
    let updated = false;
    const updatedUsers = await Promise.all(USERS.map(async (user) => {
        if (!user.password.startsWith('$2a$') && !user.password.startsWith('$2b$')) {
            updated = true;
            const hashedPassword = await bcrypt.hash(user.password, saltRounds);
            return { ...user, password: hashedPassword };
        }
        return user;
    }));
    
    if (updated) {
        USERS = updatedUsers;
        saveUsers(USERS);
        console.log('Updated users with hashed passwords');
    }
    return updatedUsers;
}

// Run once on server start
updateExistingUsers().catch(console.error);

// Demo data initialization
const DEMO_REPORTS = [];
const DEMO_UPLOADS = [];
const DEMO_LOGS = [];

// Make demo data available globally for API routes
global.DEMO_REPORTS = DEMO_REPORTS;
global.DEMO_UPLOADS = DEMO_UPLOADS;
global.DEMO_LOGS = DEMO_LOGS;

function getDemoUsernames() {
    // Read usernames and fullNames from users.json
    try {
        const users = loadUsers();
        return {
            usernames: users.map(u => u.username),
            fullNames: users.map(u => u.fullName)
        };
    } catch {
        return { usernames: ['Smith', 'user1'], fullNames: ['Jane Smith', 'Test User'] };
    }
}

const {usernames: DEMO_USERNAMES, fullNames: DEMO_FULLNAMES} = getDemoUsernames();

function getDemoReports() {
    return Array.from({length: 50}, (_, i) => ({
        id: i+1,
        title: `Report #${i+1}`,
        type: i%2===0 ? 'Financial' : 'Operational',
        user: DEMO_FULLNAMES[i % DEMO_FULLNAMES.length],
        date: new Date(Date.now() - i*86400000).toISOString().slice(0,10)
    }));
}

function getDemoUploads() {
    return Array.from({length: 30}, (_, i) => ({
        id: i+1,
        filename: `file${i+1}.pdf`,
        type: i%2===0 ? 'Invoice' : 'Contract',
        user: DEMO_FULLNAMES[i % DEMO_FULLNAMES.length],
        date: new Date(Date.now() - i*43200000).toISOString().slice(0,10)
    }));
}

function getDemoLogs() {
    return Array.from({length: 80}, (_, i) => ({
        id: i+1,
        action: i%2===0 ? 'Login' : 'Upload',
        user: DEMO_FULLNAMES[i % DEMO_FULLNAMES.length],
        date: new Date(Date.now() - i*21600000).toISOString().slice(0,10)
    }));
}

function paginate(arr, page=1, limit=10) {
    const start = (page-1)*limit;
    return {
        total: arr.length,
        results: arr.slice(start, start+limit)
    };
}

function filterData(arr, {search, type, user, dateFrom, dateTo}) {
    return arr.filter(item => {
        let ok = true;
        if (search) ok = ok && Object.values(item).some(v => String(v).toLowerCase().includes(search.toLowerCase()));
        if (type) ok = ok && item.type === type;
        if (user) ok = ok && item.user === user;
        if (dateFrom) ok = ok && item.date >= dateFrom;
        if (dateTo) ok = ok && item.date <= dateTo;
        return ok;
    });
}

// Middleware to protect private routes
function requireLogin(req, res, next) {
    if (!req.session.loggedIn || !req.session.user) {
        return res.redirect('/');
    }
    next();
}

// Test Kafka route
app.get('/test-kafka', async (req, res) => {
    try {
        await producer.send({
            topic: 'user-actions',
            messages: [{
                key: 'test-key',
                value: JSON.stringify({
                    action: 'test.message',
                    message: 'Hello Kafka!',
                    timestamp: new Date().toISOString()
                })
            }]
        });
        res.send('Test message sent to Kafka! Check your server console for the received message.');
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).send('Error sending message to Kafka');
    }
});

// Login route with proper session handling
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Load users from file
        const users = loadUsers();
        const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (!user) {
            console.log('Login failed: User not found -', username);
            return res.status(401).send('Invalid username or password');
        }
        
        // Compare password with bcrypt
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login failed: Invalid password for user -', username);
            return res.status(401).send('Invalid username or password');
        }
        
        // Update last login time
        user.lastLogin = new Date().toLocaleString();
        saveUsers(users);
        
        // Set session variables
        req.session.loggedIn = true;
        req.session.user = {
            id: user.id || user.username,
            username: user.username,
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            lastLogin: user.lastLogin
        };
        
        console.log('Login successful for user:', user.username);
        
        // Send login event to Kafka
        try {
            await producer.send({
                topic: 'user-actions',
                messages: [{
                    key: user.id || user.username,
                    value: JSON.stringify({
                        action: 'user.login',
                        userId: user.id || user.username,
                        username: user.username,
                        timestamp: new Date().toISOString(),
                        userAgent: req.headers['user-agent']
                    })
                }]
            });
        } catch (kafkaError) {
            console.error('Error sending Kafka message:', kafkaError);
            // Don't fail the login if Kafka fails
        }
        
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Error during login');
    }
});
// Example logout route with Kafka integration
app.post('/logout', async (req, res) => {
    if (req.session.userId) {
        // Send logout event to Kafka
        await producer.send({
            topic: 'user-actions',
            messages: [{
                key: req.session.userId,
                value: JSON.stringify({
                    action: 'user.logout',
                    userId: req.session.userId,
                    username: req.session.username,
                    timestamp: new Date().toISOString()
                })
            }]
        });
    }
    
    // Destroy the session
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});

// Routes
app.get('/', (req, res) => {
    if (req.session.loggedIn) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/dashboard', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.get('/uploads', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'uploads.html'));
});

// API endpoint for user info
app.get('/api/user', requireLogin, (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.session.user.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

app.get('/api/reports', requireLogin, (req, res) => {
    const {search, type, user, dateFrom, dateTo, page=1, limit=10} = req.query;
    let data = filterData(getDemoReports(), {search, type, user, dateFrom, dateTo});
    res.json(paginate(data, Number(page), Number(limit)));
});

app.get('/api/uploads', requireLogin, (req, res) => {
    const {search, type, user, dateFrom, dateTo, page=1, limit=10} = req.query;
    let data = filterData(getDemoUploads(), {search, type, user, dateFrom, dateTo});
    res.json(paginate(data, Number(page), Number(limit)));
});

app.get('/api/logs', requireLogin, (req, res) => {
    const {search, action, user, dateFrom, dateTo, page=1, limit=10} = req.query;
    let data = filterData(getDemoLogs(), {search, type: action, user, dateFrom, dateTo});
    res.json(paginate(data, Number(page), Number(limit)));
});

// Profile view/edit API
app.get('/api/profile', requireLogin, (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.session.user.username);
    if (!user) return res.status(404).json({error: 'User not found'});
    res.json(user);
});
app.post('/api/profile', requireLogin, (req, res) => {
    const { fullName, email, role } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === req.session.user.username);
    if (!user) return res.status(404).json({error: 'User not found'});
    user.fullName = fullName;
    user.email = email;
    user.role = role;
    saveUsers(users);
    req.session.user.fullName = fullName;
    req.session.user.email = email;
    req.session.user.role = role;
    res.json({success: true, user}); // Return updated user object
});

// --- User Management API (Admin only) ---
const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'Admin') return next();
    return res.status(403).json({ error: 'Forbidden' });
};

// Get all users
app.get('/api/users', requireLogin, isAdmin, (req, res) => {
    const users = loadUsers();
    res.json(users);
});

// Add new user
app.post('/api/users', requireLogin, isAdmin, async (req, res) => {
    const { username, password, fullName, email, role } = req.body;
    if (!username || !password || !fullName || !email || !role) {
        return res.status(400).json({ error: 'All fields required' });
    }
    const users = loadUsers();
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ error: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    users.push({ username, password: hashedPassword, fullName, email, role, lastLogin: null });
    saveUsers(users);
    res.json({ success: true });
});

// Edit user
app.put('/api/users/:username', requireLogin, isAdmin, async (req, res) => {
    const { username } = req.params;
    const { password, fullName, email, role } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (password) {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        user.password = hashedPassword;
    }
    if (fullName) user.fullName = fullName;
    if (email) user.email = email;
    if (role) user.role = role;
    saveUsers(users);
    res.json({ success: true });
});

// Delete user
app.delete('/api/users/:username', requireLogin, isAdmin, (req, res) => {
    const { username } = req.params;
    let users = loadUsers();
    if (!users.find(u => u.username === username)) {
        return res.status(404).json({ error: 'User not found' });
    }
    users = users.filter(u => u.username !== username);
    saveUsers(users);
    res.json({ success: true });
});

// --- DEMO DATA GENERATION/RESET ENDPOINTS ---
app.post('/api/demo/generate', requireLogin, (req, res) => {
    const { count } = req.body;
    const users = loadUsers();
    const fullNames = users.map(u => u.fullName);
    global.DEMO_REPORTS = Array.from({length: count || 50}, (_, i) => ({
        id: i+1,
        title: `Report #${i+1}`,
        type: i%2===0 ? 'Financial' : 'Operational',
        user: fullNames[i % fullNames.length],
        date: new Date(Date.now() - i*86400000).toISOString().slice(0,10)
    }));
    global.DEMO_UPLOADS = Array.from({length: Math.floor((count||50)*0.6)}, (_, i) => ({
        id: i+1,
        filename: `file${i+1}.pdf`,
        type: i%2===0 ? 'Invoice' : 'Contract',
        user: fullNames[i % fullNames.length],
        date: new Date(Date.now() - i*43200000).toISOString().slice(0,10)
    }));
    global.DEMO_LOGS = Array.from({length: (count||50)*2}, (_, i) => ({
        id: i+1,
        action: i%2===0 ? 'Login' : 'Upload',
        user: fullNames[i % fullNames.length],
        date: new Date(Date.now() - i*21600000).toISOString().slice(0,10)
    }));
    res.json({success:true});
});
app.post('/api/demo/clear', requireLogin, (req, res) => {
    global.DEMO_REPORTS = [];
    global.DEMO_UPLOADS = [];
    global.DEMO_LOGS = [];
    res.json({success:true});
});

// Example route that uses Kafka producer
app.post('/api/track-action', requireLogin, async (req, res) => {
    try {
        const { action, data } = req.body;
        
        await producer.send({
            topic: 'user-actions',
            messages: [
                {
                    key: req.session.userId,
                    value: JSON.stringify({
                        action,
                        data,
                        timestamp: new Date().toISOString(),
                        userId: req.session.userId,
                        userAgent: req.headers['user-agent']
                    })
                },
            ],
        });

        res.json({ success: true, message: 'Action tracked successfully' });
    } catch (error) {
        console.error('Error tracking action:', error);
        res.status(500).json({ success: false, error: 'Failed to track action' });
    }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    await Promise.all([
        producer.disconnect(),
        consumer.disconnect(),
    ]);
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received. Shutting down gracefully...');
    await Promise.all([
        producer.disconnect(),
        consumer.disconnect(),
    ]);
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received. Shutting down gracefully...');
    await Promise.all([
        producer.disconnect(),
        consumer.disconnect(),
    ]);
    process.exit(0);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

app.use(bodyParser.json());
app.use('/api/auth', authRoutes);

// Connect to MongoDB and start server
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  // The server is already started above, so you may remove this duplicate listen
  // Optionally, you can log MongoDB connection success here
  console.log("MongoDB connected successfully");
})
.catch(err => console.error("MongoDB connection error:", err));

app.use('/api/auth', authRoutes); // ✅ Mounts /dashboard at /api/auth/dashboard
