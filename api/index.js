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
// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '../public')));

// Database Path
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/tmp/notes.db'
  : './notes.db';

let db = null;

// Async function to initialize the database
async function initializeDb() {
  if (db) {
    console.log('Database already initialized.');
    return;
  }

  return new Promise((resolve, reject) => {
    const newDb = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        console.error('Database connection error:', err);
        return reject(err);
      }
      console.log('Connected to the SQLite database.');

      // Run database initialization in serial mode
      newDb.serialize(() => {
        // Check for existing tables to prevent re-creation
        newDb.get("SELECT name FROM sqlite_master WHERE type='table' AND name='tenants'", (err, row) => {
          if (err) {
            console.error('Database query error:', err);
            newDb.close();
            return reject(err);
          }

          if (!row) {
            console.log('Creating database tables and inserting test data...');
            newDb.run(`CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, subscription_plan TEXT DEFAULT 'free', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
            newDb.run(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, tenant_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (tenant_id) REFERENCES tenants (id))`);
            newDb.run(`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, content TEXT, user_id INTEGER NOT NULL, tenant_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id), FOREIGN KEY (tenant_id) REFERENCES tenants (id))`);
            newDb.run(`CREATE TABLE subscription_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, tenant_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', admin_comment TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id), FOREIGN KEY (tenant_id) REFERENCES tenants (id))`, () => {
              // Insert test data after all tables are created
              const hashedPassword = bcrypt.hashSync('password', 10);
              const stmt1 = newDb.prepare("INSERT OR IGNORE INTO tenants (slug, name) VALUES (?, ?)");
              stmt1.run('acme', 'Acme Corp');
              stmt1.run('globex', 'Globex Inc');
              stmt1.finalize();

              const stmt2 = newDb.prepare("INSERT OR IGNORE INTO users (email, password_hash, role, tenant_id) VALUES (?, ?, ?, ?)");
              stmt2.run('admin@acme.test', hashedPassword, 'admin', 1);
              stmt2.run('user@acme.test', hashedPassword, 'member', 1);
              stmt2.run('admin@globex.test', hashedPassword, 'admin', 2);
              stmt2.run('user@globex.test', hashedPassword, 'member', 2, (err) => {
                stmt2.finalize();
                if (err) {
                  console.error('Failed to insert test data:', err);
                  newDb.close();
                  return reject(err);
                }
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
  });
}

// Routes
// Authentication
app.post('/auth/login', (req, res) => {
  // Ensure db is available
  if (!db) {
    return res.status(503).json({ error: 'Server is initializing. Please try again.' });
  }
  // ... (rest of the /auth/login route logic)
});

// ... (Rest of the Express routes)

// Vercel Handler with DB initialization check
const handler = serverless(async (req, res) => {
  // Ensure DB is initialized before handling the request
  await initializeDb();
  return app(req, res);
});

// Local development
if (process.env.NODE_ENV !== 'production') {
  initializeDb().then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  }).catch(err => {
    console.error('Failed to start server due to database error:', err);
    process.exit(1);
  });
}

module.exports = app;
module.exports.handler = handler;