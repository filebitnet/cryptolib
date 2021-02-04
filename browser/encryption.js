const utils = require('./utils');

module.exports.mergeKeyIv = (key, iv) => {
  utils.assert_uint8(key, 'key is not an uint8array');
  utils.assert_uint8(iv, 'iv is not an uint8array');

  const byteLength = key.byteLength + iv.byteLength;
  let buf = new ArrayBuffer(key.byteLength + iv.byteLength + 1);
  let view = new Uint8Array(buf);
  const viewKey = new DataView(key.buffer);
  const viewIv = new DataView(iv.buffer);
  view[0] = 1;
  for (let i = 0; i < byteLength; ++i) {
    let posInBuf = Math.floor(i / 2);
    let bit = (i % 2) ? viewKey.getUint8(posInBuf) : viewIv.getUint8(posInBuf);
    view[(i + 1)] = bit;
  }
  return view;
}

module.exports.unmergeKeyIv = (buf) => {
  utils.assert_uint8(buf, 'buf is not an uint8array');
  if (!!((buf.byteLength - 1) % 2)) {
    throw new Error("unmergeKeyIv buf is invalid length is: " + buf.byteLength);
  }
  let view = new DataView(buf.buffer);
  const version = view.getUint8(0);
  const byteLength = (buf.byteLength - 1);
  const key = new Uint8Array(byteLength / 2);
  const iv = new Uint8Array(byteLength / 2);

  for (let i = 0; i < byteLength; ++i) {
    let bit = view.getUint8((1 + i));
    let posInBuf = Math.floor(i / 2);
    if (i % 2) {
      key[posInBuf] = bit;
    } else {
      iv[posInBuf] = bit;
    }
  }

  return {
    version: version,
    key: key,
    iv: iv
  }
};