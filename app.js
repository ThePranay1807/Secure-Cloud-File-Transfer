const express = require('express');
require('dotenv').config();
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const archiver = require('archiver');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/css', express.static(path.join(__dirname, 'css')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Saurabh@9854',
  database: 'trial'
});

// Multer config
const upload = multer({ dest: 'uploads/' });

// Routes
app.get('/Signup', (req, res) => res.render('Signup'));
app.get('/login', (req, res) => res.render('login'));

app.post('/Signup', (req, res) => {
  const { name, username, email, password } = req.body;
  const personalKey = crypto.randomBytes(32).toString('hex');

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.send('Password hash error.');
    const sql = `INSERT INTO users (name, username, email, password, personal_key) VALUES (?, ?, ?, ?, ?)`;
    db.query(sql, [name, username, email, hashedPassword, personalKey], (err) => {
      if (err) return res.send('Signup failed. Username or email exists.');

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Personal Key',
        text: `Hello ${name},\n\nYour personal key:\n${personalKey}\nKeep it safe.`
      };

      nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
      }).sendMail(mailOptions, () => {
        res.send('Signup successful. Personal key sent to email.');
      });
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    if (req.accepts('html')) {
      return res.render('login', { error: 'Username and password required' });
    } else {
      return res.status(400).json({ error: 'Username and password required' });
    }
  }

  db.query(`SELECT * FROM users WHERE username = ?`, [username], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      if (req.accepts('html')) {
        return res.render('login', { error: 'Database error' });
      } else {
        return res.status(500).json({ error: 'Database error' });
      }
    }

    if (results.length === 0) {
      if (req.accepts('html')) {
        return res.render('login', { error: 'User not found' });
      } else {
        return res.status(401).json({ error: 'User not found' });
      }
    }

    const user = results[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (err) {
        console.error('Password comparison error:', err);
        if (req.accepts('html')) {
          return res.render('login', { error: 'Authentication error' });
        } else {
          return res.status(500).json({ error: 'Authentication error' });
        }
      }

      if (!match) {
        if (req.accepts('html')) {
          return res.render('login', { error: 'Wrong password' });
        } else {
          return res.status(401).json({ error: 'Wrong password' });
        }
      }

      req.session.user = { 
        id: user.id, 
        username: user.username, 
        email: user.email 
      };

      if (req.accepts('html')) {
        return res.redirect('/layout');
      } else {
        return res.json({
          success: true,
          user: { 
            id: user.id, 
            username: user.username, 
            email: user.email 
          }
        });
      }
    });
  });
});

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/layout', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('layout', { uploadedKey: null, fileFound: null });
});

// Fixed upload route
app.post('/upload', upload.single('file'), (req, res) => {
  try {
    const { downloadLimit, userId } = req.body;
    const sessionUser = req.session.user;
    const finalUserId = sessionUser ? sessionUser.id : userId;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    if (!finalUserId) {
      return res.status(400).json({ error: 'Missing userId. Please login again.' });
    }

    const checkUserSql = 'SELECT personal_key FROM users WHERE id = ?';
    db.query(checkUserSql, [finalUserId], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error: ' + err.message });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: 'User not found. Please login again.' });
      }

      const personalKey = results[0].personal_key;
      const secureKey = uuidv4();
      
      // Validate downloadLimit
      const validatedDownloadLimit = parseInt(downloadLimit) || 1;
      if (isNaN(validatedDownloadLimit)) {
        return res.status(400).json({ error: 'Invalid download limit value' });
      }

      const insertSql = `
        INSERT INTO files (filename, filepath, secure_key, personal_key, download_limit)
        VALUES (?, ?, ?, ?, ?)
      `;

      db.query(
        insertSql,
        [req.file.originalname, req.file.filename, secureKey, personalKey, validatedDownloadLimit],
        (err2) => {
          if (err2) {
            console.error('Insert error:', err2);
            return res.status(500).json({ error: 'File upload failed: ' + err2.message });
          }

          return res.json({ 
            success: true,
            secureKey: secureKey,
            filename: req.file.originalname,
            downloadLimit: validatedDownloadLimit
          });
        }
      );
    });
  } catch (error) {
    console.error('Upload error:', error);
    return res.status(500).json({ error: 'Upload failed: ' + error.message });
  }
});

app.post('/download', (req, res) => {
  const { secure_key } = req.body;
  const sql = `SELECT * FROM files WHERE secure_key = ?`;
  db.query(sql, [secure_key], (err, results) => {
    if (err || results.length === 0) {
      return res.render('layout', { uploadedKey: null, fileFound: 'notfound' });
    }

    const file = results[0];

    if (file.download_limit <= 0) {
      return res.render('layout', {
        uploadedKey: null,
        fileFound: 'limit_exceeded'
      });
    }

    const filePath = path.join(__dirname, 'uploads', file.filepath);
    if (!fs.existsSync(filePath)) {
      return res.send('File not found on server.');
    }

    db.query(`UPDATE files SET download_limit = download_limit - 1 WHERE id = ?`, [file.id], (updateErr) => {
      if (updateErr) return res.send('Failed to update download count.');
      res.download(filePath, file.filename);
    });
  });
});

app.get('/multi_download', (req, res) => {
  res.render('multi_download', { files: null, fetched: false });
});

app.post('/fetch-files', (req, res) => {
  const { personal_key } = req.body;
  const sql = `SELECT * FROM files WHERE personal_key = ?`;
  db.query(sql, [personal_key], (err, results) => {
    if (err) return res.send('Error fetching files.');
    res.render('multi_download', { files: results, fetched: true });
  });
});

app.post('/download-selected', (req, res) => {
  const selected = Array.isArray(req.body.selectedFiles)
    ? req.body.selectedFiles
    : [req.body.selectedFiles];

  if (!selected || selected.length === 0) return res.send('No files selected.');

  const placeholders = selected.map(() => '?').join(',');
  const sql = `SELECT filepath, filename FROM files WHERE filepath IN (${placeholders})`;

  db.query(sql, selected, (err, results) => {
    if (err || results.length === 0) return res.send('Files not found.');

    res.setHeader('Content-Disposition', 'attachment; filename="selected_files.zip"');
    const archive = archiver('zip');
    archive.pipe(res);

    results.forEach(file => {
      const fullPath = path.join(__dirname, 'uploads', file.filepath);
      if (fs.existsSync(fullPath)) {
        archive.file(fullPath, { name: file.filename });
      }
    });

    archive.finalize();
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  if (req.accepts('html')) {
    res.status(500).render('error', { error: 'Internal server error' });
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use((req, res) => {
  if (req.accepts('html')) {
    res.status(404).render('404', { url: req.originalUrl });
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});