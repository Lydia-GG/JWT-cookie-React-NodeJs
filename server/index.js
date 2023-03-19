const express = require('express');
const users = require('./data.js');
const verify = require('./verify.js');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const app = express();

const corsOptions = {
  origin: true, //included origin as true
  credentials: true, //included credentials as true
};

app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

let refreshTokens = [];

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'jwtkey', {
    expiresIn: '15m',
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'refreshKey', {
    expiresIn: '15m',
  });
};

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find((user) => {
    return user.username === username && user.password === password;
  });
  if (user) {
    // Generate an access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    });
    console.log(req.cookies.access_token);
    res.status(200).json({
      user: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(400).json('User not found');
  }
});

// Delete user

app.delete('/api/users/:id', verify, (req, res) => {
  if (req.user.id === req.params.id || req.user.isAdmin) {
    res.status(200).json('user has been deleted');
  } else {
    res.status(403).json('You are not allowed to deleted this user');
  }
});

app.post('api/refresh', (req, res) => {
  const refreshToken = req.body.token;

  if (!refreshToken) return res.status(401).json('You are not authenticated');
  if (!refreshTokens.includes(refreshToken))
    return res.status(403).json('Refresh token is not valid');

  jwt.verify(refreshToken, 'refreshKey', (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => {
      token !== refreshToken;
    });

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});

//Logout
app.post('/api/logout', verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => refreshToken !== token);
  res.status(200).json('You are logged out successfully');
});

app.listen(5000, () => console.log(`server is running...`));
