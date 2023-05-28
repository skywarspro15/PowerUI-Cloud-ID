const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const jwt = require('jsonwebtoken');
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const qrCode = require('qrcode');
const cors = require('cors');
const fs = require('fs');
const app = express();


const limiter = rateLimit({
  windowMs: 15 * 60 * 100,
  max: 150,
  message: "Too many requests!",
  standardHeaders: true,
  legacyHeaders: false
});

const jsonParser = bodyParser.json();

app.use(jsonParser);
app.use(limiter);
app.use(cors());

let users = {};

if (fs.existsSync("users.json")) {
  let data = fs.readFileSync("users.json");
  users = JSON.parse(data);
} else {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2))
}

const secretKey = crypto.randomBytes(32).toString('hex');
const encSecret = process.env.ENC_KEY;
const b64Key = crypto.createHash('sha256').update(String(encSecret)).digest('base64');
const algorithm = 'aes-256-ctr';
const ENCRYPTION_KEY = Buffer.from(b64Key, 'base64');
const IV_LENGTH = 16;

function encrypt(text) {
  let iv = crypto.randomBytes(IV_LENGTH);
  let cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  let textParts = text.split(':');
  let iv = Buffer.from(textParts.shift(), 'hex');
  let encryptedText = Buffer.from(textParts.join(':'), 'hex');
  let decipher = crypto.createDecipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function authenticator(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
    return res.json({ "error": true, "message": "Authentication failed" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      res.status(403);
      return res.json({ "error": true, "message": "Authentication failed" });
    }

    req.user = decoded;
    next();
  });
}

function generateStatus() {
  let decider = Math.floor(Math.random() * 6);
  if (decider == 1) {
    return "Hello, I'm new here!";
  }
  if (decider == 2) {
    return "Hey there, just signed up!";
  }
  if (decider == 3) {
    return "Just joined in!";
  }
  if (decider == 4) {
    return "Just got here!";
  }
  if (decider == 5) {
    return "Hello, world!";
  }
}


app.get("/ping", (req, res) => {
  return res.send("Pong!");
})

app.get("/getUser", authenticator, (req, res) => {
  res.send(users[req.user.username]["public"]);
});

app.get("/getQR", authenticator, (req, res) => {
  let curUser = req.user.username;
  let rawEnc = users[curUser]["2fa"];
  let decKey = decrypt(rawEnc);
  const qrCodeUrl = speakeasy.otpauthURL({
    secret: decKey,
    label: curUser,
    issuer: 'PowerUI Cloud ID',
  });
  qrCode.toFileStream(res, qrCodeUrl, { type: 'png' });
});

app.post("/change2fa", authenticator, (req, res) => {
  let curUser = req.user.username;
  let rawEnc = users[curUser]["2fa"];
  let decKey = decrypt(rawEnc);
  const { enabled, code } = req.body;
  const verified = speakeasy.totp.verify({
    secret: decKey,
    encoding: 'ascii',
    token: code.trim(),
  });
  let token = speakeasy.totp({
    secret: decKey,
    encoding: 'ascii'
  })
  if (!verified) {
    return res.json({ "error": true, "message": "Invalid code inputted" });
  }
  users[curUser]["2faEnabled"] = enabled;
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
  res.json({ "error": false, "message": "Successfully changed 2FA status" });
});

app.post("/status", authenticator, (req, res) => {
  let data = req.body;
  if (req.user.username in users) {
    users[req.user.username]["public"]["status"] = data.status;
    fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
    res.json({ "error": false, "message": "Successfully set status" });
  } else {
    res.status(500);
    return res.json({ "error": true, "message": "Invalid user" });
  }
});

app.post("/signup", (req, res) => {
  let { username, password } = req.body;
  if (username in users) {
    res.status(500);
    return res.json({ "error": true, "message": "User already exists" });
  }
  let twoFA = speakeasy.generateSecret();
  let encrypted = encrypt(twoFA.base32);
  bcrypt.hash(password, 10, (err, hash) => {
    let randomizedStatus = generateStatus();
    users[username] = { "auth": hash, "2fa": encrypted, "2faEnabled": false, "public": { "bio": "There's currently no bio for this profile.", "active": true, "status": randomizedStatus } };
    fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
    return res.json({ "error": false, "message": "Successfully created account" });
  });
});

app.post('/login', (req, res) => {
  let { username, password, code } = req.body;

  if (username in users) {

    let hash = users[username]["auth"];

    bcrypt.compare(password, hash, (err, result) => {
      if (err) {
        res.status(403);
        return res.json({ "error": true, "message": "Authentication failed" });
      }
      if (!result) {
        res.status(401);
        return res.json({ "error": true, "message": "Invalid password." });
      }
      const is2faEnabled = users[username]["2faEnabled"];
      if (is2faEnabled) {
        let rawEnc = users[username]["2fa"];
        let decKey = decrypt(rawEnc);
        const verified = speakeasy.totp.verify({
          secret: decKey,
          encoding: 'ascii',
          token: code.trim(),
        });
        if (verified) {
          const token = jwt.sign({ username }, secretKey, { expiresIn: '24h' });
          return res.json({ "error": false, token });
        }
        return res.json({ "error": true, "message": "Two factor auth code required" });
      }
      const token = jwt.sign({ username }, secretKey, { expiresIn: '24h' });
      return res.json({ "error": false, token });
    });

  } else {
    res.status(500);
    return res.json({ "error": true, "message": "Invalid user" });
  }
});

app.listen(8080, () => {
  console.log("PowerUI Cloud ID online");
});