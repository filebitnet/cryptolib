const AES = require('./asmcrypto');
const {
  mergeKeyIv,
  unmergeKeyIv
} = require('../encryption');

const base64 = require('../base64');
const utils = require('../utils');
const sha256 = require('./sha256');

module.exports.unmergeKeyIv = unmergeKeyIv;
module.exports.mergeKeyIv = mergeKeyIv;


module.exports.nameKeySizeHash = (name, size, key) => {
  return new Promise(async resolve => {
    utils.assert_undef(name, 'name is undefined');
    utils.assert_undef(size, 'size is undefined');
    utils.assert_undef(key, 'key is undefined');
    utils.assert_uint8(key, 'key is not an uint8array');

    const key64 = base64.encode(key);
    const nkh = await sha256(utils.str_to_uint8(key + name + key));
    const encr = `{n:${name}:s${size}:k${key}`;
    const sha = await sha256(utils.str_to_uint8(encr + utils.uint8_to_hex(nkh, true)));
    return utils.uint8_to_hex(sha, true); //return lowercase
  });
}


module.exports.encrypt = (data, key, iv = false) => {
  return new Promise(resolve => {
    utils.assert_uint8(data, 'data needs to be an uint8array');
    utils.assert_uint8(key, 'key needs to be an uint8array');
    utils.assert_uint8(iv, 'iv needs to be an uint8array');

    data = new Uint8Array(data);
    key = new Uint8Array(key);
    iv = new Uint8Array(iv);
    //let iv = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    //console.log("encrypt", data, key, iv)
    let encrypted = AES.AES_CBC.encrypt(data, key, true, iv)
    return resolve(new Uint8Array(encrypted));
  });
}


module.exports.decrypt = (data, key, iv) => {
  return new Promise(resolve => {
    utils.assert_uint8(data, 'data needs to be an uint8array');
    utils.assert_uint8(key, 'key needs to be an uint8array');
    utils.assert_uint8(iv, 'iv needs to be an uint8array');
    data = new Uint8Array(data);
    key = new Uint8Array(key);
    iv = new Uint8Array(iv);
    //let iv = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    //let iv = data.slice(0, 16);
    //console.log("iv from data is", iv)
    let encrypted = data.slice();
    //console.log("decrypt", data, key, iv)
    let decrypted;
    let decrypted2;
    try {
      decrypted = AES.AES_CBC.decrypt(encrypted, key, true, iv)
    } catch (e) {}
    try {
      decrypted2 = AES.AES_CBC.decrypt(encrypted, key, false, iv);
    } catch (e) {}
    if (decrypted == undefined && decrypted2 != undefined) {
      return resolve(new Uint8Array(decrypted2));
    }
    //console.log("foo:", decrypted, decrypted2)
    return resolve(new Uint8Array(decrypted));
  });
}