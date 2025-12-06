require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');

// JSON Web Token Setup ss
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

// Configure options for the Strategy
const jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("jwt");
jwtOptions.secretOrKey = process.env.JWT_SECRET;

// Define the Strategy
const strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {

    if (jwt_payload) {
        // The following will ensure that all routes using 
        // passport.authenticate have a req.user object available to them
        // that matches the jwt_payload
        next(null, {
            _id: jwt_payload._id,
            userName: jwt_payload.userName,
        });
    } else {
        next(null, false);
    }
});

// Tell passport to use our "strategy"
passport.use(strategy);

// Add passport as application-level middleware
app.use(passport.initialize());

app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URL);

// Define User Schema & Model
const { Schema } = mongoose;

const userSchema = new Schema({
    userName: { type: String, unique: true, required: true },
    password: { type: String, required: true }, // In a real app, hash this!
    favourites: [{ type: String }] // Array of book IDs
});

const UserModel = mongoose.model("users", userSchema);

const HTTP_PORT = process.env.PORT || 8080;

// --- ROUTES ---

app.post("/register", (req, res) => {
    const newUser = new UserModel(req.body);
    newUser.save()
        .then(user => {
            res.json({ message: "User created successfully", user: user });
        })
        .catch(err => {
            res.status(422).json({ message: "Error creating user: " + err });
        });
});

app.post("/login", (req, res) => {
    UserModel.findOne({ userName: req.body.userName })
        .then(user => {
            if (user && user.password === req.body.password) { // Simple password check
                // Create payload
                const payload = {
                    _id: user._id,
                    userName: user.userName
                };
                
                // Sign token
                const token = jwt.sign(payload, process.env.JWT_SECRET);
                
                res.json({ message: "login successful", token: token });
            } else {
                res.status(422).json({ message: "Incorrect credentials" });
            }
        })
        .catch(err => {
            res.status(422).json({ message: "Error logging in: " + err });
        });
});

// Protected Routes
app.get("/favourites", passport.authenticate('jwt', { session: false }), (req, res) => {
    UserModel.findOne({ _id: req.user._id })
        .then(user => {
            res.json(user.favourites);
        })
        .catch(err => {
            res.status(500).json({ message: "Error fetching favourites" });
        });
});

app.put("/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    UserModel.updateOne(
        { _id: req.user._id },
        { $addToSet: { favourites: req.params.id } } // $addToSet prevents duplicates
    )
        .then(() => {
            // Return the updated list
            return UserModel.findOne({ _id: req.user._id });
        })
        .then(user => {
            res.json(user.favourites);
        })
        .catch(err => {
            res.status(500).json({ message: "Error adding to favourites" });
        });
});

app.delete("/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    UserModel.updateOne(
        { _id: req.user._id },
        { $pull: { favourites: req.params.id } } // $pull removes the item
    )
        .then(() => {
            return UserModel.findOne({ _id: req.user._id });
        })
        .then(user => {
            res.json(user.favourites);
        })
        .catch(err => {
            res.status(500).json({ message: "Error removing from favourites" });
        });
});

app.get("/", (req, res) => {
    res.json({ message: "User API is ONLINE" });
});


module.exports = app;








