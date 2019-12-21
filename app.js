require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// mongo database connection
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);

// mongoose schemas
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});

// passportjs + mongoose required plugins
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// mongoose models
const User = new mongoose.model("User", userSchema);

// passportjs use method
passport.use(User.createStrategy());

// passportjs serialize and deserialize methods
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

// passportjs google oauth 2.0 strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    (accessToken, refreshToken, profile, done) => {
        console.log(profile);
        
        User.findOrCreate({ googleId: profile.id }, (err, user) => {
            return done(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

// google oauth 2.0 authentitcation process with passportjs
app.get("/auth/google", passport.authenticate("google", { scope: ["https://www.googleapis.com/auth/plus.login"] }));

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        res.redirect("/secrets");
    }
);

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.post("/register", (req, res) => {

    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, err => {
        if (!err) {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        } else {
            console.log(err);
        }
    });

});

app.listen(3000, () => console.log("Server is running on port 3000."));