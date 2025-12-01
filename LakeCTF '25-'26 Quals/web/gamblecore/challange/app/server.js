const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/audio', express.static(path.join(__dirname, 'audio'))); // Serve mp3s from app root

app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Initialize wallet
app.use((req, res, next) => {
    if (!req.session.wallet) {
        req.session.wallet = {
            coins: 10e-6, // 10 microcoins
            usd: 0
        };
    }
    next();
});

// Helper for secure random float [0, 1)
function secureRandom() {
    return crypto.randomInt(0, 100000000) / 100000000;
}

app.get('/api/balance', (req, res) => {
    res.json({
        coins: req.session.wallet.coins,
        microcoins: req.session.wallet.coins * 1e6,
        usd: req.session.wallet.usd
    });
});

app.post('/api/gamble', (req, res) => {
    const { currency, amount } = req.body;
    
    if (!['coins', 'usd'].includes(currency)) {
        return res.status(400).json({ error: 'Invalid currency' });
    }

    let betAmount = parseFloat(amount);
    if (isNaN(betAmount) || betAmount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }

    const wallet = req.session.wallet;
    
    if (currency === 'coins') {
        if (betAmount > wallet.coins) {
            return res.status(400).json({ error: 'Insufficient funds' });
        }
    } else {
        if (betAmount > wallet.usd) {
            return res.status(400).json({ error: 'Insufficient funds' });
        }
    }

    // Deduct bet
    if (currency === 'coins') wallet.coins -= betAmount;
    else wallet.usd -= betAmount;

    // 9% chance to win
    const win = secureRandom() < 0.09;
    let winnings = 0;

    if (win) {
        winnings = betAmount * 10;
        if (currency === 'coins') wallet.coins += winnings;
        else wallet.usd += winnings;
    }

    res.json({
        win: win,
        new_balance: currency === 'coins' ? wallet.coins : wallet.usd,
        winnings: winnings
    });
});

app.post('/api/convert', (req, res) => {
    let { amount } = req.body;

    const wallet = req.session.wallet;
    const coinBalance = parseInt(wallet.coins);
    amount = parseInt(amount);
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    
    if (amount <= coinBalance && amount > 0) {
        wallet.coins -= amount;
        wallet.usd += amount * 0.01;
        return res.json({ success: true, message: `Converted ${amount} coins to $${(amount * 0.01).toFixed(2)}` });
    } else {
        return res.status(400).json({ error: 'Conversion failed.' });
    }
});

app.post('/api/flag', (req, res) => {
    if (req.session.wallet.usd >= 10) {
        req.session.wallet.usd -= 10;
        res.json({ flag: process.env.FLAG || 'EPFL{fake_flag}' }); 
    } else {
        res.status(400).json({ error: 'Not enough USD. You need $10.' });
    }
});

app.post('/api/deposit', (req, res) => {
    res.status(503).json({ error: 'Deposit unavailable at the moment' });
});

app.post('/api/withdraw', (req, res) => {
    res.status(503).json({ error: 'Withdrawal unavailable at the moment' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});
