const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const WS_PORT = 6001;
const JWT_SECRET = 'your-secret-key';

app.use(bodyParser.json());
app.use(express.static('public'));


// Blockchain implementation ----------------------------------------------------------------------------------------------------
class Block {
    constructor(timestamp, transactions, previousHash = '') {
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
        this.nonce = 0;
    }

    calculateHash() {
        return crypto
            .createHash('sha256')
            .update(
                this.previousHash +
                this.timestamp +
                JSON.stringify(this.transactions) +
                this.nonce
            )
            .digest('hex');
    }

    mineBlock(difficulty) {
        while (
            this.hash.substring(0, difficulty) !== Array(difficulty + 1).join('0')
        ) {
            this.nonce++;
            this.hash = this.calculateHash();
        }
    }
}

class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
        this.difficulty = 2;
        this.pendingTransactions = [];
        this.miningReward = 10;
    }

    createGenesisBlock() {
        return new Block(Date.now(), [], '0');
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    minePendingTransactions(miningRewardAddress) {
        const block = new Block(
            Date.now(),
            this.pendingTransactions,
            this.getLatestBlock().hash
        );

        block.mineBlock(this.difficulty);
        this.chain.push(block);

        // إضافة المكافأة للمعدن بعد التعدين
        this.pendingTransactions = [
            {
                from: 'network',
                to: miningRewardAddress,
                amount: this.miningReward,
            },
        ];

        return block;
    }

    addTransaction(transaction) {
        this.pendingTransactions.push(transaction); // إضافة المعاملات دون خصم الأموال هنا
    }

    getBalance(address) {
        let balance = 0;

        for (const block of this.chain) {
            for (const trans of block.transactions) {
                if (trans.from === address) {
                    balance -= trans.amount; // خصم الأموال من المرسل
                }
                if (trans.to === address) {
                    balance += trans.amount; // إضافة الأموال للمستلم
                }
            }
        }

        return balance;
    }
}

// Initialize blockchain
const blockchain = new Blockchain();

// WebSocket server for P2P network
const wss = new WebSocket.Server({ port: WS_PORT });
const sockets = [];

wss.on('connection', (socket) => {
    sockets.push(socket);
    console.log('New peer connected');

    socket.on('message', (message) => {
        const data = JSON.parse(message);
        
        if (data.type === 'NEW_BLOCK') {
            blockchain.chain.push(data.block);
            broadcast(message);
        }
    });
});

function broadcast(message) {
    sockets.forEach(socket => socket.send(message));
}

// Helper functions
function loadConfig() {
    return JSON.parse(fs.readFileSync('./users.json'));
}

function saveConfig(config) {
    fs.writeFileSync('./users.json', JSON.stringify(config, null, 2));
}

// Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Routes
app.post('/auth/login', (req, res) => {
    const config = loadConfig();
    const { username, apiKey } = req.body;
    
    const user = config.users.find(u => 
        u.username === username && u.apiKey === apiKey
    );

    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

app.get('/balance/:username', authenticateToken, (req, res) => {
    const config = loadConfig();
    const user = config.users.find(u => u.username === req.params.username);
    
    if (user) {
        res.json({ balance: user.balance });

    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

app.get('/pending-transactions', authenticateToken, (req, res) => {
    res.json({ transactions: blockchain.pendingTransactions });
});

app.post('/transaction', authenticateToken, (req, res) => {
    const config = loadConfig();
    const { to, amount } = req.body;
    const fromUsername = req.user.username;

    const fromUser = config.users.find(u => u.username === fromUsername);
    const toUser = config.users.find(u => u.username === to);

    if (!fromUser || !toUser) {
        return res.status(400).json({ error: 'Invalid user' });
    }

    if (fromUser.balance < amount) {
        return res.status(400).json({ error: 'Insufficient balance' });
    }

    // إضافة المعاملة إلى pendingTransactions فقط
    blockchain.addTransaction({
        from: fromUsername,
        to: to,
        amount: amount
    });

    // خصم المبلغ فقط عند إضافة المعاملة
    fromUser.balance -= amount;
    toUser.balance += amount;
    saveConfig(config);

    res.json({ 
        message: 'Transaction added to pending transactions',
        newBalance: fromUser.balance
    });
});

app.post('/mine', authenticateToken, (req, res) => {
    const minerUsername = req.user.username;
    
    const newBlock = blockchain.minePendingTransactions(minerUsername);
    
    // Broadcast new block to network
    broadcast(JSON.stringify({
        type: 'NEW_BLOCK',
        block: newBlock
    }));
    
    // إضافة مكافأة التعدين للمعدن
    const config = loadConfig();
    const miner = config.users.find(u => u.username === minerUsername);
    if (miner) {
        miner.balance += blockchain.miningReward; // إضافة المكافأة للمعدن فقط
        saveConfig(config);
    }
    
    res.json({ 
        message: 'Block mined successfully!',
        reward: `Mining reward of ${blockchain.miningReward} coins added to your balance`
    });
});

app.get('/blockchain', authenticateToken, (req, res) => {
    res.json({ chain: blockchain.chain });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`WebSocket server running on port ${WS_PORT}`);
});
