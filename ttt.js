const express = require("express"); // Importing express that is a web framework for Node.js also makes it easy to build web applications
const bodyParser = require("body-parser"); // Importing body-parser that is a middleware to parse incoming request
const crypto = require("crypto"); // Importing crypto that is a built-in module in Node.js for cryptographic operations
const jwt = require("jsonwebtoken"); // Importing jsonwebtoken that is a library to work with JSON Web Tokens (JWT)
const WebSocket = require("ws"); // Importing ws that is a WebSocket library for Node.js
const fs = require("fs"); // Importing fs that is a built-in module in Node.js for file system operations
const path = require("path"); // Importing path that is a built-in module in Node.js for working with file and directory paths

const app = express(); // Create an instance of express
const PORT = 3000;
const WS_PORT = 6001;
const JWT_SECRET = "your-secret-key";

app.use(bodyParser.json()); // Middleware to parse JSON bodies
app.use(express.static("public")); // Middleware to serve static files from the public directory

// Blockchain implementation
class Block {
	constructor(timestamp, transactions, previousHash = "") {
		this.timestamp = timestamp;
		this.transactions = transactions;
		this.previousHash = previousHash;
		this.hash = this.calculateHash();
		this.nonce = 0;
	}

	calculateHash() {
		return crypto
			.createHash("sha256")
			.update(
				this.previousHash +
					this.timestamp +
					JSON.stringify(this.transactions) +
					this.nonce
			)
			.digest("hex");
	}

	mineBlock(difficulty) {
		while (
			this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0")
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

	createGenesisBlock() { // Create the first block in the blockchain
		return new Block(Date.now(), [], "0");
	}

	getLatestBlock() { // Get the last block in the blockchain
		return this.chain[this.chain.length - 1];
	}

	minePendingTransactions(miningRewardAddress) { // Mine the pending transactions and add a new block to the blockchain
		const block = new Block(
			Date.now(),
			this.pendingTransactions,
			this.getLatestBlock().hash
		);

		block.mineBlock(this.difficulty);
		this.chain.push(block);

		this.pendingTransactions = [
			{
				from: "network",
				to: miningRewardAddress,
				amount: this.miningReward,
			},
		];

		return block;
	}

	addTransaction(transaction) {
		this.pendingTransactions.push(transaction);
	}

	getBalance(address) {
		let balance = 0;

		for (const block of this.chain) {
			for (const trans of block.transactions) {
				if (trans.from === address) {
					balance -= trans.amount;
				}
				if (trans.to === address) {
					balance += trans.amount;
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

wss.on("connection", (socket) => {
	sockets.push(socket);
	console.log("New peer connected");

	socket.on("message", (message) => {
		const data = JSON.parse(message);

		if (data.type === "NEW_BLOCK") {
			blockchain.chain.push(data.block);
			broadcast(message);
		}
	});
});

function broadcast(message) {
	sockets.forEach((socket) => socket.send(message));
}

// Helper functions
function loadConfig() {
	return JSON.parse(fs.readFileSync("./config.json"));
}

function saveConfig(config) {
	fs.writeFileSync("./config.json", JSON.stringify(config, null, 2));
}

// Middleware
const authenticateToken = (req, res, next) => {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.split(" ")[1];

	if (!token) return res.status(401).json({ error: "No token provided" });

	jwt.verify(token, JWT_SECRET, (err, user) => {
		if (err) return res.status(403).json({ error: "Invalid token" });
		req.user = user;
		next();
	});
};

// Routes
app.post("/auth/login", (req, res) => {
	const config = loadConfig();
	const { username, apiKey } = req.body;

	const user = config.users.find(
		(u) => u.username === username && u.apiKey === apiKey
	);

	if (!user) {
		return res.status(401).json({ error: "Invalid credentials" });
	}

	const token = jwt.sign({ username: user.username }, JWT_SECRET, {
		expiresIn: "1h",
	});
	res.json({ token });
});

app.get("/balance/:username", authenticateToken, (req, res) => {
	const config = loadConfig();
	const user = config.users.find((u) => u.username === req.params.username);

	if (user) {
		const blockchainBalance = blockchain.getBalance(req.params.username);
		res.json({ balance: user.balance + blockchainBalance });
	} else {
		res.status(404).json({ error: "User not found" });
	}
});

app.get("/pending-transactions", authenticateToken, (req, res) => {
	res.json({ transactions: blockchain.pendingTransactions });
});

app.post("/transaction", authenticateToken, (req, res) => {
	const config = loadConfig();
	const { to, amount } = req.body;
	const fromUsername = req.user.username;

	const fromUser = config.users.find((u) => u.username === fromUsername);
	const toUser = config.users.find((u) => u.username === to);

	if (!fromUser || !toUser) {
		return res.status(400).json({ error: "Invalid user" });
	}

	if (fromUser.balance < amount) {
		return res.status(400).json({ error: "Insufficient balance" });
	}

	blockchain.addTransaction({
		from: fromUsername,
		to: to,
		amount: amount,
	});

	fromUser.balance -= amount;
	toUser.balance += amount;
	saveConfig(config);

	res.json({
		message: "Transaction added to pending transactions",
		newBalance: fromUser.balance,
	});
});

app.post("/mine", authenticateToken, (req, res) => {
	const minerUsername = req.user.username;

	const newBlock = blockchain.minePendingTransactions(minerUsername);

	// Broadcast new block to network
	broadcast(
		JSON.stringify({
			type: "NEW_BLOCK",
			block: newBlock,
		})
	);

	res.json({
		message: "Block mined successfully!",
		reward: `Mining reward of ${blockchain.miningReward} coins will be available after next block is mined`,
	});
});

app.get("/blockchain", authenticateToken, (req, res) => {
	res.json({ chain: blockchain.chain });
});

app.listen(PORT, () => {
	console.log(`Server running on port http://localhost:${PORT}`);
	console.log(`WebSocket server running on port ${WS_PORT}`);
});
