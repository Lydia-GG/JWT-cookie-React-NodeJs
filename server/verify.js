const jwt = require('jsonwebtoken');

const verify = (req, res, next) => {
  const token = req.cookies.access_token;
  try {
    jwt.verify(token, 'jwtkey', (err, user) => {
      if (err) return res.status(403).json('Token is not valid');
      req.user = user;
      next();
    });
  } catch (err) {
    res.status(400).json('you are not authenticated');
  }
};

module.exports = verify;
