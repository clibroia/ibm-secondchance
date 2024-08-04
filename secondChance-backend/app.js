/* jshint esversion: 8 */
require('dotenv').config()
const express = require('express')
const path = require('path')
const cors = require('cors')
const pinoLogger = require('./logger')

const connectToDatabase = require('./models/db')
const { loadData } = require('./util/import-mongo/index')
loadData()

const app = express()
app.use('*',cors())

const port = 3060

// Connect to MongoDB; we just do this one time
connectToDatabase().then(() => {
  pinoLogger.info('Connected to DB')
})
  .catch((e) => console.error('Failed to connect to DB', e))

app.use(express.json());
// Serve static files from the 'public' directory
app.use('/images', express.static(path.join(__dirname, 'public/images')));

// Route files
const secondChanceItemsRoutes = require('./routes/secondChanceItemsRoutes');
const searchRoutes = require('./routes/searchRoutes');

// Import the authRoutes and store in a constant called authRoutes
const authRoutes = require('./routes/authRoutes');

const pinoHttp = require('pino-http');
const logger = require('./logger');

app.use(pinoHttp({ logger }));

// Use Routes
app.use('/api/secondchance/items', secondChanceItemsRoutes);
app.use('/api/secondchance/search', searchRoutes);
// Add the authRoutes and to the server by using the app.use() method.
app.use('/api/auth', authRoutes);

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send('Internal Server Error');
});

app.get("/",(req,res)=>{
    res.send("Inside the server")
})

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
