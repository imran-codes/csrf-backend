// csrfMiddleware.js

const crypto = require('crypto');

/**
 * Custom CSRF Middleware
 */
const csrfMiddleware = (req, res, next) => {
  const TOKEN_SECRET = 'my_very_secure_secret_key'; // Change this to a strong secret key

  // Utility function to create a unique CSRF token
  const createCsrfToken = () => {
    return crypto.randomBytes(32).toString('hex'); // Generate a random 32-byte token
  };

  // Utility function to hash the CSRF token
  const hashToken = (token) => {
    return crypto.createHmac('sha256', TOKEN_SECRET).update(token).digest('hex');
  };

  // 1. Check if the incoming request is a GET request
  if (req.method === 'GET') {
    const csrfToken = createCsrfToken(); // Create a new CSRF token
    const csrfTokenHash = hashToken(csrfToken);

    // Store the hash in a secure, HttpOnly cookie (not accessible by JavaScript)
    res.cookie('csrf_token', csrfTokenHash, {
      httpOnly: true,
      sameSite: 'Strict',  // Prevents cross-site cookie usage
      secure: process.env.NODE_ENV === 'production', // Use Secure flag in production
    });

    // Expose the raw CSRF token in a non-HttpOnly cookie for frontend access
    res.cookie('csrf_token_client', csrfToken, {
      sameSite: 'Strict',
      secure: process.env.NODE_ENV === 'production',
    });

    return next();
  }

  // 2. For POST, PUT, and DELETE requests, verify the CSRF token
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const csrfTokenClient = req.headers['x-csrf-token']; // Token from the client request
    const csrfTokenServer = req.cookies['csrf_token']; // Hashed token from server-side cookie

    if (!csrfTokenClient || !csrfTokenServer) {
      return res.status(403).json({ error: 'Missing CSRF token' });
    }

    // 3. Validate the CSRF token
    const csrfTokenClientHash = hashToken(csrfTokenClient);
    if (csrfTokenClientHash !== csrfTokenServer) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    return next();
  }

  next();
};

module.exports = csrfMiddleware;
