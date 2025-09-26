const express = require('express');
//const fetch = require('node-fetch'); // optional in Node < 18
const app = express();
const port = 3000;

//app.use(express.json());

// Enable CORS for all origins
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Generalized proxy route
app.all('/api/proxy', async (req, res) => {
  try {
    const { url, method, headers, body } = req.body;

    if (!url) return res.status(400).json({ error: 'Target URL is required' });

    // Forward request to external API
    const response = await fetch(url, {
      method: method || 'GET',
      headers: { ...headers },
      body: body && method !== 'GET' && method !== 'HEAD' ? JSON.stringify(body) : undefined,
    });

    // Forward JSON or text responses
    const contentType = response.headers.get('content-type');
    let data;
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
      res.status(response.status).json(data);
    } else {
      data = await response.text();
      res.status(response.status).send(data);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Proxy failed', details: err.message });
  }
});

app.get('/', (req, res) => res.send('Dynamic API Proxy Running!'));

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
