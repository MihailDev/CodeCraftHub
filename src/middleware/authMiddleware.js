const jwt = require('jsonwebtoken');

// Middleware to check JWT token
exports.verifyToken = (req, res, next) => {
    const token = req.headers['authorization']; // Extract token from the Authorization header
    if (!token) {
        return res.status(403).json({ error: 'No token provided' }); // Return error if no token is provided
    }

    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized' }); // Return error if token verification fails
        }
        req.userId = decoded.id; // Store the user ID from the token in the request object
        next(); // Proceed to the next middleware or route handler
    });
};