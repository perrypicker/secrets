require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// mongo database connection
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });

// mongoose schemas
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

// mongoose models
const User = mongoose.model("User", userSchema);

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/register", (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, (err, hash) => {

        const newUser = new User({
            email: req.body.username,
            password: hash
        });

        newUser.save(err => {
            if (err) {
                console.log(err);
            } else {
                res.render("secrets");
            }
        });
    });
});

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username }, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                bcrypt.compare(password, foundUser.password, (err, result) => {
                    if (result === true) {
                        res.render("secrets");
                    } else {
                        console.log(err);
                    }
                });
            }
        }
    });
});

app.listen(3000, () => console.log("Server is running on port 3000."));