const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const serverless = require('serverless-http');
const path = require('path');

const app = express();
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Initialize SQLite Database
const db = new sqlite3.Database(':memory:');

// Database Schema
db.serialize(() => {
  // Tenants table
  db.run(`CREATE TABLE tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    subscription_plan TEXT DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Users table
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    tenant_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
  )`);

  // Notes table
  db.run(`CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    user_id INTEGER NOT NULL,
    tenant_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
  )`);

  // Subscription Requests table
  db.run(`CREATE TABLE subscription_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    tenant_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    admin_comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
  )`);

  // Insert test tenants
  db.run("INSERT INTO tenants (slug, name) VALUES ('acme', 'Acme Corp')");
  db.run("INSERT INTO tenants (slug, name) VALUES ('globex', 'Globex Inc')");

  // Insert test users (password: 'password')
  const hashedPassword = bcrypt.hashSync('password', 10);
  db.run("INSERT INTO users (email, password_hash, role, tenant_id) VALUES ('admin@acme.test', ?, 'admin', 1)", [hashedPassword]);
  db.run("INSERT INTO users (email, password_hash, role, tenant_id) VALUES ('user@acme.test', ?, 'member', 1)", [hashedPassword]);
  db.run("INSERT INTO users (email, password_hash, role, tenant_id) VALUES ('admin@globex.test', ?, 'admin', 2)", [hashedPassword]);
  db.run("INSERT INTO users (email, password_hash, role, tenant_id) VALUES ('user@globex.test', ?, 'member', 2)", [hashedPassword]);
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Tenant Isolation Middleware
const ensureTenantAccess = (req, res, next) => {
  const tenantSlug = req.params.tenantSlug || req.body.tenantSlug;
  
  if (tenantSlug && req.user.tenantSlug !== tenantSlug) {
    return res.status(403).json({ error: 'Access denied to this tenant' });
  }
  next();
};

// Role-based Access Control
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Routes

// Health Check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Authentication
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  db.get(`
    SELECT u.*, t.slug as tenant_slug, t.name as tenant_name, t.subscription_plan
    FROM users u 
    JOIN tenants t ON u.tenant_id = t.id 
    WHERE u.email = ?
  `, [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({
      userId: user.id,
      email: user.email,
      role: user.role,
      tenantId: user.tenant_id,
      tenantSlug: user.tenant_slug,
      subscriptionPlan: user.subscription_plan
    }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenantSlug: user.tenant_slug,
        tenantName: user.tenant_name,
        subscriptionPlan: user.subscription_plan
      }
    });
  });
});

// Notes CRUD Operations

// Create Note
app.post('/notes', authenticateToken, (req, res) => {
  const { title, content } = req.body;

  if (!title) {
    return res.status(400).json({ error: 'Title is required' });
  }

  // Admins are not limited by plan
  if (req.user.role === 'admin') {
    return createNote();
  }

  // Fetch current subscription plan from DB to ensure real-time plan is used
  db.get('SELECT subscription_plan FROM tenants WHERE id = ?', [req.user.tenantId], (err, t) => {
    if (err || !t) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (t.subscription_plan === 'free') {
      // Check subscription limits for free plan
      db.get('SELECT COUNT(*) as count FROM notes WHERE tenant_id = ?', [req.user.tenantId], (err2, result) => {
        if (err2) {
          return res.status(500).json({ error: 'Database error' });
        }

        if (result.count >= 3) {
          return res.status(403).json({ 
            error: 'Free plan limit reached. Upgrade to Pro for unlimited notes.',
            code: 'SUBSCRIPTION_LIMIT'
          });
        }

        createNote();
      });
    } else {
      createNote();
    }
  });

  function createNote() {
    db.run(
      'INSERT INTO notes (title, content, user_id, tenant_id) VALUES (?, ?, ?, ?)',
      [title, content || '', req.user.userId, req.user.tenantId],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to create note' });
        }

        db.get('SELECT * FROM notes WHERE id = ?', [this.lastID], (err, note) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to retrieve created note' });
          }
          res.status(201).json(note);
        });
      }
    );
  }
});

// Get All Notes
app.get('/notes', authenticateToken, (req, res) => {
  const isMember = req.user.role === 'member';
  const params = isMember ? [req.user.tenantId, req.user.userId] : [req.user.tenantId];
  const query = isMember
    ? 'SELECT * FROM notes WHERE tenant_id = ? AND user_id = ? ORDER BY created_at DESC'
    : 'SELECT * FROM notes WHERE tenant_id = ? ORDER BY created_at DESC';

  db.all(query, params, (err, notes) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve notes' });
    }
    res.json(notes);
  });
});

// Get Single Note
app.get('/notes/:id', authenticateToken, (req, res) => {
  const noteId = req.params.id;
  const isMember = req.user.role === 'member';
  const params = isMember ? [noteId, req.user.tenantId, req.user.userId] : [noteId, req.user.tenantId];
  const query = isMember
    ? 'SELECT * FROM notes WHERE id = ? AND tenant_id = ? AND user_id = ?'
    : 'SELECT * FROM notes WHERE id = ? AND tenant_id = ?';

  db.get(query, params, (err, note) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.json(note);
  });
});

// Update Note
app.put('/notes/:id', authenticateToken, (req, res) => {
  const noteId = req.params.id;
  const { title, content } = req.body;

  if (!title) {
    return res.status(400).json({ error: 'Title is required' });
  }

  const isMember = req.user.role === 'member';
  const params = isMember
    ? [title, content || '', noteId, req.user.tenantId, req.user.userId]
    : [title, content || '', noteId, req.user.tenantId];
  const query = isMember
    ? 'UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND tenant_id = ? AND user_id = ?'
    : 'UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND tenant_id = ?';

  db.run(query, params, function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update note' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }

    db.get('SELECT * FROM notes WHERE id = ?', [noteId], (err, note) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to retrieve updated note' });
      }
      res.json(note);
    });
  });
});

// Delete Note
app.delete('/notes/:id', authenticateToken, (req, res) => {
  const noteId = req.params.id;
  const isMember = req.user.role === 'member';
  const params = isMember ? [noteId, req.user.tenantId, req.user.userId] : [noteId, req.user.tenantId];
  const query = isMember
    ? 'DELETE FROM notes WHERE id = ? AND tenant_id = ? AND user_id = ?'
    : 'DELETE FROM notes WHERE id = ? AND tenant_id = ?';

  db.run(query, params, function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete note' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.json({ message: 'Note deleted successfully' });
  });
});

// Subscription Management
app.post('/tenants/:slug/upgrade', authenticateToken, ensureTenantAccess, requireRole(['admin']), (req, res) => {
  const tenantSlug = req.params.slug;

  db.run(
    'UPDATE tenants SET subscription_plan = "pro" WHERE slug = ?',
    [tenantSlug],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to upgrade subscription' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Tenant not found' });
      }

      // Generate new token with updated subscription plan
      const newToken = jwt.sign({
        userId: req.user.userId,
        email: req.user.email,
        role: req.user.role,
        tenantId: req.user.tenantId,
        tenantSlug: req.user.tenantSlug,
        subscriptionPlan: 'pro'
      }, JWT_SECRET, { expiresIn: '24h' });

      res.json({ 
        message: 'Successfully upgraded to Pro plan',
        token: newToken,
        subscriptionPlan: 'pro'
      });
    }
  );
});

// Serve frontend pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

app.get('/upgrade', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/upgrade.html'));
});

// Subscription Requests - Member creates request
app.post('/subscription-requests', authenticateToken, requireRole(['member']), (req, res) => {
  const userId = req.user.userId;
  const tenantId = req.user.tenantId;

  // Check for existing pending request
  db.get(
    'SELECT * FROM subscription_requests WHERE user_id = ? AND tenant_id = ? AND status = "pending" ORDER BY created_at DESC LIMIT 1',
    [userId, tenantId],
    (err, existing) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      if (existing) {
        return res.status(200).json({ message: 'Request already pending', request: { id: existing.id, status: existing.status, created_at: existing.created_at } });
      }

      db.run(
        'INSERT INTO subscription_requests (user_id, tenant_id, status) VALUES (?, ?, "pending")',
        [userId, tenantId],
        function(err) {
          if (err) return res.status(500).json({ error: 'Failed to create request' });

          db.get('SELECT id, status, created_at FROM subscription_requests WHERE id = ?', [this.lastID], (err, row) => {
            if (err) return res.status(500).json({ error: 'Failed to retrieve request' });
            res.status(201).json({ message: 'Request submitted', request: row });
          });
        }
      );
    }
  );
});

// Subscription Requests - Member views own latest request status
app.get('/subscription-requests/me', authenticateToken, requireRole(['member']), (req, res) => {
  db.get(
    'SELECT id, status, created_at, updated_at FROM subscription_requests WHERE user_id = ? AND tenant_id = ? ORDER BY created_at DESC LIMIT 1',
    [req.user.userId, req.user.tenantId],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(404).json({ error: 'No requests found' });
      res.json(row);
    }
  );
});

// Subscription Requests - Admin lists requests for their tenant
app.get('/subscription-requests', authenticateToken, requireRole(['admin']), (req, res) => {
  db.all(
    `SELECT r.id, r.status, r.created_at, r.updated_at, u.email as user_email
     FROM subscription_requests r
     JOIN users u ON u.id = r.user_id
     WHERE r.tenant_id = ?
     ORDER BY r.created_at DESC`,
    [req.user.tenantId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

// Subscription Requests - Admin approve
app.post('/subscription-requests/:id/approve', authenticateToken, requireRole(['admin']), (req, res) => {
  const requestId = req.params.id;
  db.get('SELECT * FROM subscription_requests WHERE id = ?', [requestId], (err, reqRow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!reqRow || reqRow.tenant_id !== req.user.tenantId) {
      return res.status(404).json({ error: 'Request not found' });
    }

    db.run(
      'UPDATE subscription_requests SET status = "approved", updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [requestId],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to approve request' });
        if (this.changes === 0) return res.status(404).json({ error: 'Request not found' });

        // Upgrade tenant to Pro upon approval (idempotent)
        db.run(
          'UPDATE tenants SET subscription_plan = "pro" WHERE id = ?',
          [reqRow.tenant_id],
          function(err2) {
            if (err2) return res.status(500).json({ error: 'Failed to upgrade tenant plan' });
            return res.json({ message: 'Request approved and tenant upgraded to Pro', id: requestId, status: 'approved' });
          }
        );
      }
    );
  });
});

// Subscription Requests - Admin reject
app.post('/subscription-requests/:id/reject', authenticateToken, requireRole(['admin']), (req, res) => {
  const requestId = req.params.id;
  db.get('SELECT * FROM subscription_requests WHERE id = ?', [requestId], (err, reqRow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!reqRow || reqRow.tenant_id !== req.user.tenantId) {
      return res.status(404).json({ error: 'Request not found' });
    }

    db.run(
      'UPDATE subscription_requests SET status = "rejected", updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [requestId],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to reject request' });
        if (this.changes === 0) return res.status(404).json({ error: 'Request not found' });
        res.json({ message: 'Request rejected', id: requestId, status: 'rejected' });
      }
    );
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

// Export for Vercel
module.exports = app;
module.exports.handler = serverless(app);