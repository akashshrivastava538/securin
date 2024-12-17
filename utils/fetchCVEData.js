const axios = require('axios');

const fetchCVEData = async (startIndex, resultsPerPage) => {
    const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
        params: { startIndex, resultsPerPage },
    });
    return response.data;
};

module.exports = fetchCVEData;
