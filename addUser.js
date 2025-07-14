const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const saltRounds = 10;
const usersPath = path.join(__dirname, 'users.json');

async function askQuestion(query) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise(resolve => rl.question(query, ans => {
        rl.close();
        resolve(ans);
    }));
}

async function addUser() {
    console.log('\n=== Add New User ===');
    
    // Get user input
    const username = await askQuestion('Username: ');
    const password = await askQuestion('Password: ');
    const fullName = await askQuestion('Full Name: ');
    const email = await askQuestion('Email: ');
    const role = (await askQuestion('Role (User/Admin) [User]: ')) || 'User';

    // Load existing users
    const users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));

    // Check if user exists
    if (users.some(u => u.username === username)) {
        console.error(`\n❌ Error: Username "${username}" already exists!`);
        process.exit(1);
    }

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = {
        username,
        password: hashedPassword,
        fullName,
        email,
        role: ['User', 'Admin'].includes(role) ? role : 'User',
        lastLogin: null
    };

    // Save user
    users.push(newUser);
    fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
    
    console.log('\n✅ User created successfully!');
    console.log('Username:', username);
    console.log('Full Name:', fullName);
    console.log('Email:', email);
    console.log('Role:', newUser.role);
}

// Run the script
addUser().catch(err => {
    console.error('\n❌ Error creating user:', err.message);
    process.exit(1);
});