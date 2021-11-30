/* write the code to run app.js here */
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bycrypt = require("bcrypt");
const express = require("express");
const app = express();

SECRET_TOKEN =
  "0b149fa7f1dded2f4ceef78710d12416c7ebd8884b38a420fcd3f0c193601fdd23e5e3c7b1217856d7284cda5283dcc4d56a013726c85acca993a1d9ead9f819";
app.use(express.json());

// middlewares
const {
  notFoundEndpointHandler,
  RegisterUserAlreadyExists,
  LoginUserNotExists,
} = require("./middleware");

// controllers
const {
  returnDataBase,
  saveDataBase,
  encryptPassword,
} = require("./controllers");

app.use(notFoundEndpointHandler);

const USERS = returnDataBase()["USERS"];
const INFORMATION = returnDataBase()["INFORMATION"];
const REFRESHTOKENS = returnDataBase()["REFRESHTOKENS"];

/*
     sign up to the server
*/

app.post("/users/register", RegisterUserAlreadyExists, async (req, res) => {
  USERS.push({
    email: req.body.email,
    name: req.body.name,
    password: await bycrypt.hash(req.body.password, 10),
    isAdmin: false,
  });
  INFORMATION.push({
    email: req.body.email,
    info: req.body.name,
  });
  saveDataBase(USERS, INFORMATION, REFRESHTOKENS);
  res.status(201).send("Register Success");
});

/*
     login to the server
*/
app.post("/users/login", LoginUserNotExists, (req, res) => {
  let currentUser = USERS.find(({ email }) => email === req.body.email);
  bycrypt
    .compare(req.body.password, currentUser.password)
    .then((success) => {
      loggedUser = { email: req.body.email, password: req.body.password };
      const accessToken = jwt.sign(loggedUser, SECRET_TOKEN, {
        expiresIn: "1m",
      });

      const refreshToken = jwt.sign(loggedUser, SECRET_TOKEN);

      REFRESHTOKENS.push(refreshToken);
      saveDataBase(USERS, INFORMATION, REFRESHTOKENS);
      res.status(200).json({
        accessToken: accessToken,
        refreshToken: refreshToken,
        email: currentUser.email,
        name: currentUser.name,
        isAdmin: currentUser.isAdmin,
      });
    })
    .catch((err) => {
      res.status(403).send("User or Password incorrect");
    });
});

app.post("/users/tokenValidate", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token === null) {
    res.status(401).send("Access Token Required");
  } else {
    jwt.verify(token, SECRET_TOKEN, (err, user) => {
      if (err) {
        res.status(403).send("Invalid Access Token");
      } else {
        res.status(200).json({ valid: true });
      }
    });
  }
});

module.exports = { app };
