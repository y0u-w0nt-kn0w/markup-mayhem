const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));

// Custom CSP middleware
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "connect-src 'self'; " +
    "frame-src 'none'; " +
    "object-src 'none'"
  );
  next();
});

// Challenge configuration
const FLAG_PARTS = [
  'mmuctf{d0m_x5s_',        // Basic DOM XSS
  'st0r3d_x5s_',            // Stored XSS
  's>g_x5s_',               // SVG XSS
  'c5p_byp45s!*!}'          // CSP bypass
];

const HINTS = [
  "Some elements have attributes that can run code when certain events occur",
  "The administrator has a routine inspection pattern!!!",
  "Vector graphics can be more than just pretty pictures...",
  "Our content policy trusts a popular CDN - maybe their libraries know some interesting tricks?"
];

// Track solved parts per session
const sessions = {};

// Main challenge page
app.get('/', (req, res) => {
  const sessionId = req.cookies.sessionId || Math.random().toString(36).substring(2);
  
  if (!sessions[sessionId]) {
    sessions[sessionId] = {
      solved: [],
      comments: []
    };
  }
  
  res.cookie('sessionId', sessionId, { httpOnly: true });
  
  const currentLevel = sessions[sessionId].solved.length;
  const currentHint = currentLevel < HINTS.length ? HINTS[currentLevel] : "Congratulations!";
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Markup Mayhem</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .challenge { background: #f5f5f5; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .hint { background: #e3f2fd; padding: 10px; border-left: 4px solid #2196F3; margin: 10px 0; }
        .flag { color: green; font-weight: bold; }
        .success { color: green; }
      </style>
    </head>
    <body>
      <h1>Markup Mayhem</h1>
      ${req.query.csp_success ? '<p class="success">CSP bypass detected!</p>' : ''}
      
      <div class="challenge">
        <h2>Search Portal</h2>
        <form action="/search" method="GET">
          <input type="text" name="q" placeholder="Search...">
          <button type="submit">Search</button>
        </form>
        ${req.query.q ? `<div>You searched for: ${req.query.q.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>` : ''}
        
        <h2>Comments Section</h2>
        <form action="/comment" method="POST">
          <textarea name="comment" rows="4" cols="50"></textarea><br>
          <button type="submit">Post Comment</button>
        </form>
        <div id="comments">${sessions[sessionId].comments.map(c => c.replace(/</g, '&lt;').replace(/>/g, '&gt;')).join('<br>')}</div>
        
        <h2>Profile Editor</h2>
        <div id="profileEditor">
          <form id="profileForm">
            <input type="text" id="profileInput" placeholder="Enter your profile text">
            <button type="submit">Update</button>
          </form>
          <div id="profileOutput"></div>
        </div>
        
        <h2>Avatar Upload</h2>
        <form action="/upload" method="POST" enctype="multipart/form-data">
          <input type="file" name="avatar" accept=".svg">
          <button type="submit">Upload</button>
        </form>
      </div>
      
      <div class="hint">
        ${currentLevel > 0 ? `<div class="flag">Current progress: ${sessions[sessionId].solved.map(p => FLAG_PARTS[p]).join('')}</div>` : ''}
        ${currentHint ? `<h3>Hint:</h3><p>${currentHint}</p>` : ''}
      </div>
      
      <script>
        document.getElementById('profileForm').addEventListener('submit', function(e) {
          e.preventDefault();
          const input = document.getElementById('profileInput').value;
          document.getElementById('profileOutput').textContent = input;
        });
        
        if (window.bypassSuccess) {
          fetch('/csp-bypass', { method: 'POST' });
        }
      </script>
    </body>
    </html>
  `;
  
  res.send(html);
});

// Search endpoint (DOM XSS)
app.get('/search', (req, res) => {
  const sessionId = req.cookies.sessionId;
  const searchTerm = req.query.q || '';
  
  if (searchTerm.includes('<img') && searchTerm.includes('onerror') && !sessions[sessionId].solved.includes(0)) {
    sessions[sessionId].solved.push(0);
  }
  
  res.redirect(`/?q=${encodeURIComponent(searchTerm)}`);
});

// Comment endpoint (Stored XSS)
app.post('/comment', (req, res) => {
  const sessionId = req.cookies.sessionId;
  const comment = req.body.comment || '';
  
  sessions[sessionId].comments.push(comment);
  
  if (comment.includes('cookie') && !sessions[sessionId].solved.includes(1)) {
    setTimeout(() => sessions[sessionId].solved.push(1), 15000);
  }
  
  if (comment.includes('bypassSuccess') || comment.includes('ng-include')) {
    setTimeout(() => {
      if (!sessions[sessionId].solved.includes(3)) {  // Changed index from 4 to 3
        sessions[sessionId].solved.push(3);
      }
    }, 15000);
  }
  
  res.redirect('/');
});

// CSP bypass endpoint
app.post('/csp-bypass', (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (!sessions[sessionId].solved.includes(3)) {  // Changed index from 4 to 3
    sessions[sessionId].solved.push(3);
    return res.redirect('/?csp_success=1');
  }
  res.redirect('/');
});

// Upload endpoint (SVG XSS)
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('avatar'), (req, res) => {
  const sessionId = req.cookies.sessionId;
  
  if (req.file && req.file.mimetype === 'image/svg+xml') {
    const content = fs.readFileSync(req.file.path, 'utf8');
    
    if (content.includes('<script') || 
        (content.includes('onload') && !content.toLowerCase().includes('onload='))) {
      sessions[sessionId].solved.push(2);  // Changed index from 3 to 2
    }
  }
  
  res.redirect('/');
});

// JSONP endpoint for CSP bypass
app.get('/jsonp', (req, res) => {
  const callback = req.query.callback || 'callback';
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`${callback}(${JSON.stringify({data: 'test'})})`);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Challenge running at http://localhost:${PORT}`);
});
