const {
  mergeKeyIv,
  unmergeKeyIv
} = require('./encryption');
const base64 = require('./base64');
const utils = require('./utils');
const sha256 = require('./sha256');

module.exports.unmergeKeyIv = unmergeKeyIv;
module.exports.mergeKeyIv = mergeKeyIv;


module.exports.nameKeySizeHash = async(name, size, key) => {
  utils.assert_undef(name, 'name is undefined');
  utils.assert_undef(size, 'size is undefined');
  utils.assert_undef(key, 'key is undefined');
  utils.assert_uint8(key, 'key is not an uint8array');

  const key64 = base64.encode(key);
  const nkh = await sha256(utils.str_to_uint8(key + name + key));
  const encr = `{n:${name}:s${size}:k${key}`;
  const sha = await sha256(utils.str_to_uint8(encr + utils.uint8_to_hex(nkh, true)));
  return utils.uint8_to_hex(sha, true); //return lowercase
}


module.exports.encrypt = (data, key, iv) => {
  return new Promise(async(resolve) => {
    utils.assert_uint8(data, 'data needs to be an uint8array');
    utils.assert_uint8(key, 'key needs to be an uint8array');
    utils.assert_uint8(iv, 'iv needs to be an uint8array');

    let keyimported = await crypto.subtle.importKey("raw", new Uint8Array(key), {
      name: "AES-CBC"
    }, false, ["encrypt"]);

    let encrypted = await crypto.subtle.encrypt({
      name: "AES-CBC",
      iv: new Uint8Array(iv)
    }, keyimported, data);

    resolve(new Uint8Array(encrypted));
  });
}


module.exports.decrypt = (data, key, iv) => {
  return new Promise(async(resolve) => {
    utils.assert_uint8(data, 'data needs to be an uint8array');
    utils.assert_uint8(key, 'key needs to be an uint8array');
    utils.assert_uint8(iv, 'iv needs to be an uint8array');

    data = new Uint8Array(data);
    key = new Uint8Array(key);
    iv = new Uint8Array(iv);

    let keyimported = await crypto.subtle.importKey("raw", new Uint8Array(key), {
      name: "AES-CBC"
    }, false, ["decrypt"]);

    let dec = await crypto.subtle.decrypt({
      name: "AES-CBC",
      iv,
    }, keyimported, new Uint8Array(data));

    resolve(new Uint8Array(dec));
  });
}