const utils = require('./utils');

module.exports = function(bytesIn) {
  return new Promise(async(resolve) => {
    utils.assert_uint8(bytesIn, 'input for sha256 needs to be uint8array');
    let digest = await crypto.subtle.digest('SHA-256', bytesIn);
    return resolve(new Uint8Array(digest));
  })
}