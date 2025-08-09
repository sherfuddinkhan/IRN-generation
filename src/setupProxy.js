const { createProxyMiddleware } = require('http-proxy-middleware');
//const app = express();
module.exports = function(app) {
  app.use(
    '/eicore',
    createProxyMiddleware({
      target: 'https://api.sandbox.core.irisirp.com',
      changeOrigin: true,
      pathRewrite: {
        '^/eicore': '/', // Retain /eicore in path!
      },
      logLevel: 'debug',
    })
  );
};
// Import proxy setup
//require('./setproxy')(app);

//app.listen(3000, () => console.log('Server running on port 3000'));