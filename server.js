const express = require("express");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");
const csrfMiddleware = require("./middlewares/csrfProtection");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 5001;

// Middleware setup
app.use(cookieParser()); // Parse cookies
app.use(express.json()); // Parse JSON request bodies
app.use(
  cors({
    origin: "http://localhost:3000", // React app's URL
    credentials: true, // Allows the server to send cookies and headers
  })
);

// CSRF protection middleware
const csrfProtection = csurf({ cookie: true });
app.use(csrfMiddleware); // from csurf package

app.use(csrfProtection); // from csrf middleware

// Serve the React files
app.use(express.static(path.join(__dirname, "../frontend/src/index.js")));

// Endpoint to get the CSRF token
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.cookies["csrf_token_client"] }); // Send the CSRF token to the client from the custom middleware
  // OR use the package below
  res.cookie("XSRF-TOKEN", req.csrfToken()); // Set the CSRF token in a cookie
  res.json({ csrfToken: req.csrfToken() });
});

// Example form submission endpoint
app.post("/api/submit-form", csrfProtection, (req, res) => {
  const { username } = req.body;
  console.log(`Received username: ${username}`);
  res.json({ message: "Form submitted successfully!" });
});
// Fallback to serve React app for any other routes
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/src/index.js"));
});
// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
