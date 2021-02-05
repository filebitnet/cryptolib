/** @memberof CryptoLib */

const {
  createHash
} = require('crypto');

const utils = require('./utils');

/**
 * create a sha56 Buffer from a Buffer
 *
 * @async
 * @function sha256
 * @param {buffer} Buffer - the data to be hashed as Buffer
 * @return {Promise<Buffer>} the hashed data as Buffer
 */
module.exports = (buffer) => {
  return new Promise(resolve => {
    utils.assert_buf(buffer, 'input for sha256 needs to be buffer')
    return resolve(createHash('sha256').update(buffer).digest());
  });
}