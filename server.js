const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const jwtSecret = process.env.JWT_SECRET;
const port = process.env.PORT || 3000;

// Define a cron schedule to run the function every day at 12 PM (noon) Kenyan time
cron.schedule('0 12 * * *', () => {
  getRecentJournalEntries();
}, { timezone: 'Africa/Nairobi' });
async function sendTestEmail(text, email) {
  try {
      // configure email transport
      const transporter = nodemailer.createTransport({
          host: 'smtp.gmail.com',
          port: 587,
          auth: {
              user: 'betttonny966@gmail.com',
              pass: 'xmbgugmxswhmxipf'
          }
      });
      // send email
      await transporter.sendMail({
          from: 'Random Journal Website <no-reply@random-journal.com>',
          to: email,
          subject: 'Random Journal From Other Users',
          text: text
      });
      console.log('Email sent successfully!');
  } catch (error) {
      console.error(error);
  }
} 
function getRecentJournalEntries() {
  const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000); // calculate the timestamp for 24 hours ago
  const recentEntriesByUser = {}; // create an empty object to store the recent journal entries by user
  
  // loop through all users in the database
  router.db.get('users').value().forEach(user => {
  
    // loop through all journal entries for each user
    const recentEntries = [];
    user.journals.forEach(entry => {
  
      // check if the entry was created within the last 24 hours
      if (entry.createdAt > twentyFourHoursAgo) {
        recentEntries.push({...entry}); // add the entry to the recentEntries array
      }
    });
  
    if(recentEntries.length > 0){
      recentEntriesByUser[user.id] = recentEntries; // add the recent entries to the recentEntriesByUser object
    }
  });

  // get an array of all sender and recipient IDs
  const userIds = Object.keys(recentEntriesByUser);
  
  // loop through all possible combinations of senders and recipients
  for (let i = 0; i < userIds.length; i++) {
    const senderId = userIds[i];
    const recipientIds = userIds.filter(id => id !== senderId);
    
    for (let j = 0; j < recipientIds.length; j++) {
      const recipientId = recipientIds[j];
      const recipient = router.db.get('users').find({id: recipientId}).value();

      // randomly select a journal entry from the sender and send it to the recipient
      if(recentEntriesByUser[senderId].length > 0){
        const selectedEntry = recentEntriesByUser[senderId].splice(Math.floor(Math.random() * recentEntriesByUser[senderId].length), 1)[0];
        
        // send email to recipient with the journal entry details, without showing the sender's email address
        sendTestEmail(selectedEntry.content, recipient.email)
        console.log(`To: ${recipient.email}, Journal Entry: ${selectedEntry.content}`);
      }
    }
  }
}
const middlewares = jsonServer.defaults();
// Use default middleware
server.use(middlewares);
// Parse request body to JSON
server.use(jsonServer.bodyParser);
// Custom middleware for generating createdAt field on journal creation
server.use((req, res, next) => {
  if (req.method === 'POST' && req.url === '/journals') {
    req.body.createdAt = Date.now();
  }

  // Continue to JSON Server router
  next();
});

router.get('/db', (req, res) => {
  const db = router.db;
  // Access database contents here
  res.send(db);
});
// Add custom routes
server.post('/login', async (req, res) => {
  // Retrieve the email and password from the request body
  const { email, password } = req.body;
  // Find the user based on the email
  const user = await router.db.get('users').find({ email }).value();
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  // If the user is found, compare the provided password with the stored hash using bcrypt
  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  // If the password matches, generate a JWT token and send it back
  const token = jwt.sign({ id: user.id, email:user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
  res.status(200).json({ message: 'Login successful!', token });
});

server.post('/register', (req, res) => {

    const { email, password } = req.body;
    // Check if user already exists
    const existingUser = router.db.get('users').find({ email }).value();
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }
    // Generate a new token for the user
    const saltRounds = 10;
    const passwordHash = bcrypt.hashSync(password, saltRounds); // generate a salted password hash using bcrypt

    const id = uuidv4();
    const newUser = {
      id,
      email,
      password: passwordHash, // store the salted password hash in the database
      journals: []
    };

    router.db.get('users').push(newUser).write();

    const userToken = jwt.sign({ id, email }, process.env.JWT_SECRET);

    // Return the generated token along with a success message
    res.status(201).json({ message: 'Registration successful!', token: userToken });
});


server.post('/journals', (req, res) => {
  // Verify that the user is authenticated by checking for a JWT in the Authorization header
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required!' });
  }

  // Extract the JWT token from the Authorization header
  const token = authHeader.split(' ')[1];

  try {
    // Verify the JWT and extract the user ID
    const decoded = jwt.verify(token, jwtSecret);
    const userId = decoded.id;

    // Create the new journal entry with the user ID
    const { content } = req.body;
    const createdAt = Date.now();
    const id = uuidv4();

    const newJournal = {
      id,
      createdAt,
      content,
      userId
    };

    router.db
      .get('users')
      .find({ id: userId })
      .update('journals', (journals) => journals.concat(newJournal))
      .write();

    res.status(201).json({ message: 'Journal created!', journal: newJournal });
  } catch (error) {
    // If the JWT is invalid, or if there is an error decoding it, return a 401 Unauthorized error
    res.status(401).json({ error: 'Login to send a journal anonymously and receive one too' });
  }
});

server.get('/user/journal', async (req, res) => {
  // Verify that the user is authenticated by checking for a JWT in the Authorization header
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required!' });
  }
  // Extract the JWT token from the Authorization header
  const token = authHeader.split(' ')[1];

  try {
    // Verify the JWT and extract the user ID
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Find the user's journals based on their ID
    const journals = await router.db.get('users')
      .find({ id: userId })
      .get('journals')
      .value();

    res.status(200).json({ journals });

  } catch (error) {
    // If the JWT is invalid, or if there is an error decoding it, return a 401 Unauthorized error
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});




// Handle 404 errors
server.use((req, res, next) => {
  res.status(404).json({ error: 'Not found' });
});

// Handle generic errors
server.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

server.get('/', (req, res) => {
  res.send('Hello World!, Welcome to Server')
})

// Start server
server.use(router);

server.listen(port, () => {
  console.log('JSON Server is running on port 3000');
});
