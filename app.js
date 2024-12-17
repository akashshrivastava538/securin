const express = require('express');
const cors = require('cors');
require('dotenv').config();

const cveRoutes = require('./routes/cveRoutes');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/cves', cveRoutes);

// Start the server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
