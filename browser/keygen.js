//browser keygen.js
module.exports = (bit = 128) => {
  let len = bit / 8;
  let buf = new ArrayBuffer(len);
  let rb = new Uint8Array(buf);
  let arr = new Uint8Array(len);
  window.crypto.getRandomValues(arr);
  for (let i = 0; i <= arr.length; ++i) {
    rb[i] = arr[i];
  }
  return rb;
}