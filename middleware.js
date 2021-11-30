"use strict";
const express = require("express");
const fs = require("fs");
const path = require("path");

/*
    get database
*/
function returnDataBase() {
  let dataBase = fs.readFileSync(path.resolve(__dirname, "./users.json"));
  let dataBaseJson = JSON.parse(dataBase.toString());
  return dataBaseJson;
}

/*
          save database
      */
function saveDataBase(dataBaseJson) {
  fs.writeFileSync("database.json", Buffer.from(JSON.stringify(dataBaseJson)));
}

/*
      404 middleware
*/
function notFoundEndpointHandler(req, res, next) {
  if (res.statusCode !== 404) {
    next();
  } else {
    res.status(404).send("unknown endpoint");
  }
}

/*
   The name or email already exists in db
*/

function RegisterUserAlreadyExists(req, res, next) {
  let users = returnDataBase()["USERS"];
  if (
    !users.find(({ name }) => name === req.body.name) ||
    !users.find(({ email }) => email === req.body.email)
  ) {
    next();
  } else {
    res.status(409).send("user already exists");
  }
}

function LoginUserNotExists(req, res, next) {
  let users = returnDataBase()["USERS"];
  if (users.find(({ email }) => email === req.body.email)) {
    next();
  } else {
    res.status(404).send("cannot find user");
  }
}

module.exports = {
  notFoundEndpointHandler,
  RegisterUserAlreadyExists,
  LoginUserNotExists,
};
