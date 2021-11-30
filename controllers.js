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
function saveDataBase(users, information, refreshtokens) {
  fs.writeFileSync(
    "users.json",
    Buffer.from(
      JSON.stringify({
        USERS: users,
        INFORMATION: information,
        REFRESHTOKENS: refreshtokens,
      })
    )
  );
}

/*
        passwordEncrypt
  */
async function encryptPassword(password) {
  try {
    const hashedPassword = await bycrypt.hash(password, 10);
    return hashedPassword;
  } catch (e) {
    res.status(500).json({ message: "password creation failed" });
  }
}

module.exports = { returnDataBase, saveDataBase, encryptPassword };
