// src/setupProxy.js
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  app.use(
    '/eicore', // This is the path prefix that will trigger the proxy
    createProxyMiddleware({
      target: 'https://api.sandbox.core.irisirp.com', // The base URL of your API
      changeOrigin: true, // Needed for virtual hosted sites
      secure: false, // Set to true for production, false if you have self-signed certs or issues with sandbox
      pathRewrite: {
        '^/eicore': '', // Rewrite the path if needed, here it's a direct match
      },
    })
  );
};