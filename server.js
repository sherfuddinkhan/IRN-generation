const express = require('express');
const cors = require('cors'); // Required for Cross-Origin Resource Sharing
// const fetch = require('node-fetch'); // Uncomment this line if using Node.js < 18

const app = express();
const port = 3000;

// ===================================
// 1. CORS CONFIGURATION
// Explicitly allow all required custom headers from the React client.
// ===================================
app.use(cors({
    // Allow all origins for development
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 'Authorization', 
        // Custom headers required by the e-invoicing API
        'client_id', 'client_secret', 'Gstin', 'sup_gstin', 'irp', 'user_name', 'AuthToken' 
    ],
    optionsSuccessStatus: 204 // Use 204 for successful pre-flight OPTIONS requests
}));

// ===================================
// 2. Body Parsing Middleware
// Required to parse the JSON body sent by the client's fetch request.
// ===================================
app.use(express.json());

// Generalized API Proxy Route
app.post('/api/proxy', async (req, res) => {
    try {
        // The client sends: { targetUrl: '...', method: 'GET', headers: { ... } }
        const { targetUrl, url, method, headers, body } = req.body;
        
        // Use targetUrl (preferred) or url (as a fallback)
        const finalUrl = targetUrl || url;

        if (!finalUrl) {
            return res.status(400).json({ error: 'Target URL is required in the request body (targetUrl or url).' });
        }

        // Determine if the external request requires a body (only for non-GET/HEAD methods)
        const requestHasBody = body && method && method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'HEAD';
        
        // Final request options for the external API
        const fetchOptions = {
            method: method || 'GET',
            headers: { ...headers },
            // Only include body if the method is not GET/HEAD and a body payload exists
            body: requestHasBody ? JSON.stringify(body) : undefined, 
        };
        
        // Ensure Content-Type is set for requests with a body
        if (requestHasBody && !fetchOptions.headers['Content-Type'] && !fetchOptions.headers['content-type']) {
            fetchOptions.headers['Content-Type'] = 'application/json';
        }

        console.log(`Proxying ${fetchOptions.method} to: ${finalUrl}`);
        
        // 1. Forward request to external API
        const response = await fetch(finalUrl, fetchOptions);

        // 2. Forward status, headers, and body back to the client
        const contentType = response.headers.get('content-type');
        
        // Copy all headers from the target response back to the client response
        response.headers.forEach((value, name) => {
            res.set(name, value);
        });

        // Forward status code
        res.status(response.status);

        // Forward JSON or text responses
        if (contentType && contentType.includes('application/json')) {
            const data = await response.json();
            res.json(data);
        } else {
            const data = await response.text();
            res.send(data);
        }

    } catch (err) {
        console.error('Proxy Error:', err.message);
        // Send a 500 status code for internal proxy failures
        res.status(500).json({ 
            error: 'Proxy failed to connect or process the response.', 
            details: err.message 
        });
    }
});

// Simple GET route for status check
app.get('/', (req, res) => res.send('Dynamic API Proxy Running! Send a POST request to /api/proxy.'));

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));