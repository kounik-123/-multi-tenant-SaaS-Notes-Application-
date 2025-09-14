const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const serverless = require('serverless-http');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// Database Path
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/tmp/notes.db'
  : './notes.db';

let db = null;

// Initialize Database Function
async function initializeDb() {
  return new Promise((resolve, reject) => {
    // Open a new database connection
    const newDb = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        console.error('Database connection error:', err);
        return reject(err);
      }
      console.log('Connected to the SQLite database.');

      // Check if tables exist
      newDb.get("SELECT name FROM sqlite_master WHERE type='table' AND name='tenants'", (err, row) => {
        if (err) {
          console.error('Database query error:', err);
          return reject(err);
        }

        if (!row) {
          // Tables don't exist, create them
          console.log('Creating database tables and inserting test data...');
          newDb.serialize(() => {
            newDb.run(`CREATE TABLE tenants (...)`); // Add your CREATE TABLE SQL here
            newDb.run(`CREATE TABLE users (...)`);
            newDb.run(`CREATE TABLE notes (...)`);
            newDb.run(`CREATE TABLE subscription_requests (...)`);
            
            // Test data (password: 'password')
            const hashedPassword = bcrypt.hashSync('password', 10);
            newDb.run("INSERT OR IGNORE INTO tenants (slug, name) VALUES ('acme', 'Acme Corp')");
            newDb.run("INSERT OR IGNORE INTO tenants (slug, name) VALUES ('globex', 'Globex Inc')");
            newDb.run("INSERT OR IGNORE INTO users (email, password_hash, role, tenant_id) VALUES ('admin@acme.test', ?, 'admin', 1)", [hashedPassword]);
            newDb.run("INSERT OR IGNORE INTO users (email, password_hash, role, tenant_id) VALUES ('user@acme.test', ?, 'member', 1)", [hashedPassword]);
            newDb.run("INSERT OR IGNORE INTO users (email, password_hash, role, tenant_id) VALUES ('admin@globex.test', ?, 'admin', 2)", [hashedPassword]);
            newDb.run("INSERT OR IGNORE INTO users (email, password_hash, role, tenant_id) VALUES ('user@globex.test', ?, 'member', 2)", [hashedPassword], (err) => {
              if (err) return reject(err);
              console.log('Database initialized with test data.');
              db = newDb;
              resolve();
            });
          });
        } else {
          console.log('Database tables already exist.');
          db = newDb;
          resolve();
        }
      });
    });
  });
}

// ... (Rest of your middleware and routes remain the same)

// Wrap the app in an async function to ensure DB is initialized before handling requests
const handler = serverless(async (req, res) => {
  if (!db) {
    await initializeDb();
  }
  return app(req, res);
});

// For local development
if (process.env.NODE_ENV !== 'production') {
  initializeDb().then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  });
}

// Export for Vercel
module.exports = app;
module.exports.handler = handler;