import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import session from 'express-session';
import dotenv from 'dotenv';
import connectPgSimple from 'connect-pg-simple';

// 1. Config & Setup
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const { Pool } = pg;

// --- CRITICAL FIX FOR VERCEL ---
// This tells Express to trust the Vercel Load Balancer.
// Without this, the 'secure' cookie will NOT be set, and you will get a login loop.
app.set('trust proxy', 1);
// -------------------------------

// 2. Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for most cloud DBs
});

// 3. Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true })); // Parse form data
app.use(express.json());

// --- VIEW ENGINE SETUP (FIXED) ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Explicitly set views path for Vercel
// ---------------------------------

// 4. Session Configuration
const PgSession = connectPgSimple(session);

app.use(session({
    store: new PgSession({
      pool : pool,                // Use existing DB connection
      tableName : 'session',      // Default table name
      createTableIfMissing: true  // Create table if not exists (Safety check)
    }),
    secret: process.env.SESSION_SECRET || 'dev_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // True only in HTTPS/Prod
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        sameSite: 'lax' // CSRF protection
    } 
}));

// 5. Authentication Middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.user) return next();
    res.redirect('/login');
};

// --- ROUTES ---

// Root: Redirect based on auth status
app.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('home');
});

// Login Page
app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/dashboard');
    res.render('login', { error: null });
});

// Login Logic
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const validPass = await bcrypt.compare(password, user.password_hash);
            if (validPass) {
                // Save user info in session
                req.session.user = { id: user.id, username: user.username };
                // Explicitly save session before redirecting (Best practice for Vercel/Async stores)
                req.session.save(err => {
                    if(err) console.error(err);
                    res.redirect('/dashboard');
                });
                return;
            }
        }
        res.render('login', { error: 'Invalid email or password' });
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Server error occurred' });
    }
});

// Register Page
app.get('/register', (req, res) => {
    if (req.session.user) return res.redirect('/dashboard');
    res.render('register', { error: null });
});

// Register Logic
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
            [username, email, hash]
        );
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        if (err.code === '23505') { 
            return res.render('register', { error: 'Email or Username already exists' });
        }
        res.render('register', { error: 'Registration failed' });
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// PROTECTED DASHBOARD
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.session.user });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});