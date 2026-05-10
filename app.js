require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

const Joi = require("joi");
const mongoSanitizer = require('mongo-sanitizer').default;

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const {database} = require('./databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

const expireTime = 60 * 60 * 1000;

function isAuthenticated(req) {
    return req.session.authenticated;
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/public"));
app.use(express.json());

app.use(mongoSanitizer(
    {replaceWith: '_'}
));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false, 
    resave: true,
}));

app.get('/', (req, res) => {
    if (!isAuthenticated(req)) {
        res.send(`
            <h1>Welcome</h1>
            <a href='/signup'><button>Sign up</button></a>
            <a href='/login'><button>Log in</button></a>
        `);
    } else {
        res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href='/members'><button>Go to Members Area</button></a>
            <a href='/logout'><button>Logout</button></a>
        `);
    }
});

app.get('/signup', (req, res) => {
    res.send(`
        <h2>Create User</h2>
        <form action='/signupSubmit' method='post'>
            <input name='name' type='text' placeholder='name'><br>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({name, email, password});
    if (validationResult.error != null) {
        res.send(`Error: ${validationResult.error.message}. <a href='/signup'>Try again</a>`);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({name: name, email: email, password: hashedPassword});
    
    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.send(`
        <h2>Log in</h2>
        <form action='/loginSubmit' method='post'>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        res.send("User not found. <a href='/login'>Try again</a>");
        return;
    }

    const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, _id: 1}).toArray();

    if (result.length != 1) {
        res.send("User not found. <a href='/login'>Try again</a>");
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    } else {
        res.send("Invalid password. <a href='/login'>Try again</a>");
    }
});

app.get('/members', (req, res) => {
    if (!isAuthenticated(req)) {
        res.redirect('/');
        return;
    }

    const randomImage = getRandomInt(1, 3);
    res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src='/cat${randomImage}.gif' style='width:250px;'><br>
        <a href='/logout'><button>Sign out</button></a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
