const path = require('path');

module.exports = {
  entry: './crypto.web.js',
  target: false,
  mode: 'production',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'crypto.module.js',
    libraryTarget: 'umd'
  },
  optimization: {
    moduleIds: 'deterministic',
    minimize: true
  }
};