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
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/css', express.static(path.join(__dirname, 'css')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Mysql@1807',
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
  db.query(`SELECT * FROM users WHERE username = ?`, [username], (err, results) => {
    if (err || results.length === 0) return res.send('Login failed.');
    const user = results[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (!match) return res.send('Wrong password.');
      req.session.user = { id: user.id, username: user.username, email: user.email };
      res.redirect('/layout');
    });
  });
});

// LAYOUT PAGE
app.get('/layout', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('layout', { uploadedKey: null, fileFound: null });
});

// Upload a file
app.post('/upload', upload.single('file'), (req, res) => {
  const { limit } = req.body;
  const user = req.session.user;
  if (!user || !req.file) return res.redirect('/login');

  const secureKey = uuidv4();
  const sql = `INSERT INTO files (filename, filepath, secure_key, personal_key, download_limit) 
               VALUES (?, ?, ?, (SELECT personal_key FROM users WHERE id = ?), ?)`;
  db.query(sql, [req.file.originalname, req.file.filename, secureKey, user.id, limit], (err) => {
    if (err) return res.send('File upload failed.');
    res.render('layout', { uploadedKey: secureKey, fileFound: null });
  });
});

// Download with secure key
app.post('/download', (req, res) => {
  const { secure_key } = req.body;
  const sql = `SELECT * FROM files WHERE secure_key = ?`;
  db.query(sql, [secure_key], (err, results) => {
    if (err || results.length === 0) {
      return res.render('layout', { uploadedKey: null, fileFound: 'notfound' });
    }

    const file = results[0];

    // Check download limit
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

    // Decrease limit by 1
    db.query(`UPDATE files SET download_limit = download_limit - 1 WHERE id = ?`, [file.id], (updateErr) => {
      if (updateErr) return res.send('Failed to update download count.');
      res.download(filePath, file.filename); // Preserve original filename
    });
  });
});

// MULTI-DOWNLOAD PAGE
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

//  Updated route: Download selected files with correct filenames
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
        archive.file(fullPath, { name: file.filename }); //  Use original filename
      }
    });

    archive.finalize();
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
