require('dotenv').config(); // Load environment variables

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const usersFilePath = path.join(__dirname, 'users.json');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true
}));

// Load users from users.json file if it exists
let users = [];
if (fs.existsSync(usersFilePath)) {
    const data = fs.readFileSync(usersFilePath);
    users = JSON.parse(data);
}

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
    if (req.session.user) {
        next(); // User is authenticated, continue to the next middleware or route handler
    } else {
        res.redirect('/sign-in'); // Redirect to sign-in page if not authenticated
    }
}

// Middleware to check if user is admin
function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.username === 'admin') {
        next(); // User is admin, continue to the next middleware or route handler
    } else {
        res.status(403).send('Access denied'); // Access denied if not admin
    }
}

// Routes
app.get('/', (req, res) => res.sendFile(__dirname + '/public/index.html'));
app.get('/about', (req, res) => res.sendFile(__dirname + '/public/about.html'));
app.get('/contact', (req, res) => res.sendFile(__dirname + '/public/contact.html'));
app.get('/admission', (req, res) => res.sendFile(__dirname + '/public/admission.html'));
app.get('/signup', (req, res) => res.sendFile(__dirname + '/public/signup.html'));
app.get('/sign-in', (req, res) => res.sendFile(__dirname + '/public/sign-in.html'));

// Dashboard route (accessible only after sign-in)
app.get('/LACIPD_TECH', requireAuth, (req, res) => {
    res.sendFile(__dirname + '/public/LACIPD_TECH.html');
});

// Sign-up route
app.post('/signup', (req, res) => {
    const { username, password, firstName, lastName, phoneNumber, email } = req.body;

    // Hash the password
    const hashedPassword = bcrypt.hashSync(password, 8);

    // Load existing users data from users.json
    const usersData = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));

    // Check if username already exists
    const existingUser = usersData.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).send('User already exists');
    }

    // Add new user to users array
    usersData.push({ username, password: hashedPassword, firstName, lastName, phoneNumber, email });

    // Save updated users data back to users.json
    fs.writeFileSync(usersFilePath, JSON.stringify(usersData, null, 2));

    // Redirect or send response as needed
    res.redirect('/sign-in');
});

// Route to fetch usernames
app.get('/users', (req, res) => {
    // Read and parse users.json
    fs.readFile(usersFilePath, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error reading users data');
        }

        // Parse JSON data
        const usersData = JSON.parse(data);

        // Extract usernames
        const usernames = usersData.map(user => user.username);

        // Return usernames as JSON response
        res.json(usernames);
    });
});

// Sign-in route
app.post('/sign-in', (req, res) => {
    const { username, password } = req.body;

    // Load existing users data from users.json
    const usersData = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));

    // Find the user by username
    const user = usersData.find(user => user.username === username);

    // If user not found or password does not match, handle error
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).send('Invalid username or password');
    }

    // Set user session
    req.session.user = { username: user.username };

    // Redirect based on user type
    if (user.username === 'admin') {
        res.redirect('/view-users');
    } else {
        res.redirect('/LACIPD_TECH');
    }
});

// Route to get username for dashboard
app.get('/get-username', requireAuth, (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({ username: req.session.user.username });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Failed to log out.');
        }
        res.redirect('/sign-in'); // Redirect to sign-in page after logging out
    });
});

// Route to view-users
app.get('/view-users', requireAuth, requireAdmin, (req, res) => {
    fs.readFile(usersFilePath, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error reading users data');
        }
        const usersData = JSON.parse(data);

        // Format users data for display
        const formattedUsers = usersData.map(user => ({
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            phoneNumber: user.phoneNumber,
            email: user.email
        }));

        res.json(formattedUsers); // Send formatted users data as JSON
    });
});

// Transporter for sending emails
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL_USER, // your email
        pass: process.env.EMAIL_PASS  // your email password
    }
});

// Password recovery route
app.get('/recover-password', (req, res) => res.sendFile(__dirname + '/public/recover-password.html'));

app.post('/recover-password', (req, res) => {
    const { email } = req.body;

    // Load existing users data from users.json
    const usersData = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));

    // Find the user by email
    const user = usersData.find(user => user.email === email);

    // If user not found, handle error
    if (!user) {
        return res.status(404).send('Email not found');
    }

    // Generate a temporary password
    const tempPassword = Math.random().toString(36).slice(-8);
    const hashedTempPassword = bcrypt.hashSync(tempPassword, 8);

    // Update user with the temporary password
    user.password = hashedTempPassword;

    // Save updated users data back to users.json
    fs.writeFileSync(usersFilePath, JSON.stringify(usersData, null, 2));

    // Send the temporary password to the user's email
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Recovery',
        text: `Your temporary password is: ${tempPassword}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.error(error);
        }
        console.log('Email sent: ' + info.response);
        res.send('Temporary password sent to your email');
    });
});

// Username recovery route
app.get('/recover-username', (req, res) => res.sendFile(__dirname + '/public/recover-username.html'));

app.post('/recover-username', (req, res) => {
    const { email } = req.body;

    // Load existing users data from users.json
    const usersData = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));

    // Find the user by email
    const user = usersData.find(user => user.email === email);

    // If user not found, handle error
    if (!user) {
        return res.status(404).send('Email not found');
    }

    // Send the username to the user's email
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Username Recovery',
        text: `Your username is: ${user.username}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.error(error);
        }
        console.log('Email sent: ' + info.response);
        res.send('Username sent to your email');
    });
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));




