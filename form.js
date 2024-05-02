const express = require('express');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');
const { DynamoDBClient, PutItemCommand, GetItemCommand } = require('@aws-sdk/client-dynamodb');
const { fromIni } = require('@aws-sdk/credential-provider-ini');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const credentials = fromIni({profile: "sandbox"});
const region = "us-east-1";
const dynamoDBClient = new DynamoDBClient({ region, credentials });

app.use(express.static(path.join(__dirname, 'public')));

// Registration route - GET request for /register.html
app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
            throw new Error('Username and password are required');
        }

    const hashedPassword = await bcrypt.hash(password, 10); 
    const params = {
        TableName: 'sbox-login',
        Item: { 
            username: { S: username }, 
            password: { S: hashedPassword } 
        }
    };
    try {
        await dynamoDBClient.send(new PutItemCommand(params));
        res.send('User registered successfully');
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).send('Error registering user');
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const params = {
        TableName: 'sbox-login',
        Key: { username: { S: username } }
    };
    try {
        const data = await dynamoDBClient.send(new GetItemCommand(params));
        if (!data.Item) {
            res.status(401).send('Invalid username or password');
            return;
        }
        const hashedPassword = data.Item.password.S;
        const passwordMatch = await bcrypt.compare(password, hashedPassword);
        if (passwordMatch) {
            const sessionToken = 'sample_session_token';
            res.cookie('sessionToken', sessionToken, { httpOnly: true });
            res.send('Login successful');
        } else {
            res.status(401).send('Invalid username or password');
        }
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).send('Error logging in');
    }
});


const authenticate = (req, res, next) => {
    const sessionToken = req.cookies.sessionToken;
    if (sessionToken === 'sample_session_token') {
        next(); 
    } else {
        res.status(401).send('Unauthorized');
    }
};


app.get('/dashboard', authenticate, (req, res) => {
    res.send('Welcome to the dashboard!');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
