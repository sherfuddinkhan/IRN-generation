const { createProxyMiddleware } = require('http-proxy-middleware');
module.exports = function(app) {
  app.use(
    '/eivital',
    createProxyMiddleware({
      target: 'https://api.sandbox.core.irisirp.com',
      changeOrigin: true,
      pathRewrite: {
        '^/eivital': '/',  // <--- retain /eivital in path!
      },
      logLevel: 'debug',
    })
  );
  app.use(
    '/eicore',
    createProxyMiddleware({
      target: 'https://api.sandbox.core.irisirp.com',
      changeOrigin: true,
      pathRewrite: {
       '^/eicore': '/',   // <--- retain /eicore in path!
      },
      logLevel: 'debug',
    })
  );
};
