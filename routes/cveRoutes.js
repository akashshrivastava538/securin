const express = require('express');
const { fetchCVEList, fetchCVEDetails } = require('../controllers/cveController');

const router = express.Router();

// Route to fetch paginated CVE List
router.get('/list', fetchCVEList);

// Route to fetch CVE details by ID
router.get('/details/:id', fetchCVEDetails);

module.exports = router;
