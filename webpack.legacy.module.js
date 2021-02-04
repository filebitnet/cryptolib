const path = require('path');

module.exports = {
  entry: './crypto.web.legacy.js',
  target: false,
  mode: 'production',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'crypto.legacy.module.js',
    libraryTarget: 'umd'
  },
  optimization: {
    moduleIds: 'deterministic',
    minimize: true
  }
};