const {
  is_str,
  is_uint8,
  str_to_buffer,
  buffer_to_str,
  assert_uint8
} = require('./utils');

function uint8ToBase64(buffer) {
  assert_uint8(buffer, 'uint8toBase64 input needs to be uint8array');
  var binary = '';
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(base64) {
  var binary_string = atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes;
}

const encode_url = (str) => {
  return String(str)
    .replace(/\+/gi, '-')
    .replace(/\//gi, '_')
    .replace(/=/gi, '');
};

module.exports.encode = (buf) => {
  if (is_str(buf)) {
    buf = str_to_buffer(buf);
  }
  return encode_url(uint8ToBase64(buf));
};

const decode_url = (str) => {
  return String(str)
    .replace(/\-/gi, '+')
    .replace(/_/gi, '/');
};

module.exports.decode = (str, uint8 = true) => {
  str = decode_url(str);
  if (uint8) {
    return base64ToUint8(str);
  } else {
    return atob(str);
  }
};