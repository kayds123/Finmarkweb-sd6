const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  fullName: String,
  username: String,
  role: String,
  lastLogin: String,
  mfa: {
    secret: String,
    enabled: { type: Boolean, default: false }
  }
});

module.exports = mongoose.model('User', userSchema);


[
  {
    "username": "user",
    "password": "$2b$10$4XVWjI4Z5i/O7vrVGM6EuuwfOrYe4rkl7Qetawu7F8bxUXNp/VGyq",
    "fullName": "John Doe",
    "email": "user@example.com",
    "role": "User",
    "lastLogin": null
  },
  {
    "username": "admin",
    "password": "$2b$10$bO7VayVHnwFlSDbdssnGS.98Aak3ClArBrkEXjdQjo3RpSug2fKgG",
    "fullName": "Jane Admin",
    "email": "admin@example.com",
    "role": "Admin",
    "lastLogin": null
  },
  {
    "username": "John",
    "password": "$2b$10$M0AOd9mWWW8dHjkQKf0YsesXI3Dzk41ttUBbT1HBuYYOrjnSaF.Qq",
    "fullName": "John",
    "email": "john@gmail.com",
    "role": "User",
    "lastLogin": "7/7/2025, 9:37:13 PM"
  },
  {
    "username": "user1",
    "password": "$2a$12$Ya9/q4OI./eHtEQYw0Z8UO43mfNbJxqFIZ9mqHgnh6n85eVZkzJ/S",
    "fullName": "Hello Love",
    "email": "hellolove@example.com",
    "role": "User",
    "lastLogin": null
  }
]