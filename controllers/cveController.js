const axios = require('axios');

// Format date as per required format
const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric'
    });
};

// Fetch CVE List with Pagination
exports.fetchCVEList = async (req, res) => {
    const { page = 1, limit = 10 } = req.query;

    try {
        const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
            params: { startIndex: (page - 1) * limit, resultsPerPage: limit },
        });

        const data = response.data.vulnerabilities.map(v => ({
            id: v.cve.id || 'N/A',
            identifier: v.cve.sourceIdentifier || 'Unknown',
            publishedDate: formatDate(v.cve.published) || 'Unknown Date',
            lastModifiedDate: formatDate(v.cve.lastModified) || 'Unknown Date',
            status: v.cve.vulnStatus || 'Unspecified',
            description:v.cve.descriptions || 'No description available',
            severity:v.cve.baseSeverity|| 'LOW',
            score:v.cve.score || '7.2',
            vectorString:v.cve.vectorString || 'AV:N\/AC:L\/Au:N\/C:C\/I:C\/A:C',
            accessVector: v.cve.accessVector || 'N/A',
            accessComplexity: v.cve.accessComplexity || 'N/A',
            authentication: v.cve.authentication || 'N/A',
            confidentialityImpact: v.cve.confidentialityImpact || 'N/A',
            integrityImpact: v.cve.integrityImpact || 'N/A',
            availabilityImpact: v.cve.availabilityImpact || 'N/A',
            exploitabilityScore: v.cve.exploitabilityScore || 0,
            impactScore: v.cve.impactScore || 0,
            criteria:v.cve.criteria,
            matchCriteriaId:v.cve.matchCriteriaId,
            vulnerable:v.cve



        }));

        res.status(200).json({
            page: Number(page),
            limit: Number(limit),
            totalResults: response.data.totalResults,
            data,
        });
    } catch (error) {
        console.error('Error fetching CVE list:', error.message);
        res.status(500).json({ error: 'Failed to fetch CVE list.' });
    }
};

// Fetch CVE details by ID
exports.fetchCVEDetails = async (req, res) => {
    const { id } = req.params;

    try {
        const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
            params: { cveId: id },
        });

        const cve = response.data.vulnerabilities[0];
        if (!cve) {
            return res.status(404).json({ error: `CVE with ID ${id} not found.` });
        }

        const details = {
            id: cve.cve.id,
            description: cve.cve.descriptions[0]?.value || 'No description available',
            severity: cve.metrics?.cvssMetricV2?.baseSeverity || 'LOW',
            score: cve.metrics?.cvssMetricV2?.cvssData?.baseScore || 0,
            vectorString: cve.metrics?.cvssMetricV2?.cvssData?.vectorString || 'N/A',
            accessVector: cve.metrics?.cvssMetricV2?.cvssData?.accessVector || 'N/A',
            accessComplexity: cve.metrics?.cvssMetricV2?.cvssData?.accessComplexity || 'N/A',
            authentication: cve.metrics?.cvssMetricV2?.cvssData?.authentication || 'N/A',
            confidentialityImpact: cve.metrics?.cvssMetricV2?.cvssData?.confidentialityImpact || 'N/A',
            integrityImpact: cve.metrics?.cvssMetricV2?.cvssData?.integrityImpact || 'N/A',
            availabilityImpact: cve.metrics?.cvssMetricV2?.cvssData?.availabilityImpact || 'N/A',
            exploitabilityScore: cve.metrics?.cvssMetricV2?.exploitabilityScore || 0,
            impactScore: cve.metrics?.cvssMetricV2?.impactScore || 0,
            cpe: cve.cpeMatch ? cve.cpeMatch.map(item => item.cpe23Uri) : [],
        };

        res.status(200).json(details);
    } catch (error) {
        console.error(`Error fetching details for CVE ${id}:`, error.message);
        res.status(500).json({ error: 'Failed to fetch CVE details.' });
    }
};
