const path = require('path');

module.exports = {
  entry: './crypto.web.legacy.js',
  mode: 'production',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'crypto.legacy.js',
    scriptType: 'text/javascript',
    library: "filebitCrypto"
  },
  optimization: {
    moduleIds: 'deterministic',
    minimize: true
  }
};