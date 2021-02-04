const utils = require('../utils');
module.exports = function(bytesIn) {
  return new Promise(resolve => {
    utils.assert_uint8(bytesIn, 'input for sha256 needs to be uint8array');

    //var t = typeof bytesIn;
    //if(t != 'Uint8Array') throw 'Expected Uint8Array but got a '+t; //this check wont work because its like a map of index to byte

    var chunks = Math.floor((bytesIn.byteLength + 9 + 63) / 64); //512 bit each

    //Copy bytesIn[] into b[], then pad bit1, then pad bit0s,
    //then append int64 bit length, finishing the last block of 512 bits.
    //byte b[] = new byte[chunks*64];
    var b = new Uint8Array(chunks * 64);

    //System.arraycopy(bytesIn, 0, b, 0, bytesIn.byteLength);
    b.set(bytesIn, 0);

    b[bytesIn.byteLength] = 0x80;

    //long bitLenTemp = bytesIn.byteLength*8;
    var bitLenTemp = bytesIn.byteLength * 8; //in js, this has float64 precision, which is more than enough for Uint8Array size
    for (var i = 7; i >= 0; i--) {
      b[b.byteLength - 8 + i] = bitLenTemp & 0xff;
      bitLenTemp >>>= 8;
    }

    var a = new Uint32Array(136);
    a[0] = 0x428a2f98;
    a[1] = 0x71374491;
    a[2] = 0xb5c0fbcf;
    a[3] = 0xe9b5dba5;
    a[4] = 0x3956c25b;
    a[5] = 0x59f111f1;
    a[6] = 0x923f82a4;
    a[7] = 0xab1c5ed5;
    a[8] = 0xd807aa98;
    a[9] = 0x12835b01;
    a[10] = 0x243185be;
    a[11] = 0x550c7dc3;
    a[12] = 0x72be5d74;
    a[13] = 0x80deb1fe;
    a[14] = 0x9bdc06a7;
    a[15] = 0xc19bf174;
    a[16] = 0xe49b69c1;
    a[17] = 0xefbe4786;
    a[18] = 0x0fc19dc6;
    a[19] = 0x240ca1cc;
    a[20] = 0x2de92c6f;
    a[21] = 0x4a7484aa;
    a[22] = 0x5cb0a9dc;
    a[23] = 0x76f988da;
    a[24] = 0x983e5152;
    a[25] = 0xa831c66d;
    a[26] = 0xb00327c8;
    a[27] = 0xbf597fc7;
    a[28] = 0xc6e00bf3;
    a[29] = 0xd5a79147;
    a[30] = 0x06ca6351;
    a[31] = 0x14292967;
    a[32] = 0x27b70a85;
    a[33] = 0x2e1b2138;
    a[34] = 0x4d2c6dfc;
    a[35] = 0x53380d13;
    a[36] = 0x650a7354;
    a[37] = 0x766a0abb;
    a[38] = 0x81c2c92e;
    a[39] = 0x92722c85;
    a[40] = 0xa2bfe8a1;
    a[41] = 0xa81a664b;
    a[42] = 0xc24b8b70;
    a[43] = 0xc76c51a3;
    a[44] = 0xd192e819;
    a[45] = 0xd6990624;
    a[46] = 0xf40e3585;
    a[47] = 0x106aa070;
    a[48] = 0x19a4c116;
    a[49] = 0x1e376c08;
    a[50] = 0x2748774c;
    a[51] = 0x34b0bcb5;
    a[52] = 0x391c0cb3;
    a[53] = 0x4ed8aa4a;
    a[54] = 0x5b9cca4f;
    a[55] = 0x682e6ff3;
    a[56] = 0x748f82ee;
    a[57] = 0x78a5636f;
    a[58] = 0x84c87814;
    a[59] = 0x8cc70208;
    a[60] = 0x90befffa;
    a[61] = 0xa4506ceb;
    a[62] = 0xbef9a3f7;
    a[63] = 0xc67178f2;
    a[64] = 0x6a09e667;
    a[65] = 0xbb67ae85;
    a[66] = 0x3c6ef372;
    a[67] = 0xa54ff53a;
    a[68] = 0x510e527f;
    a[69] = 0x9b05688c;
    a[70] = 0x1f83d9ab;
    a[71] = 0x5be0cd19;
    for (var chunk = 0; chunk < chunks; chunk++) {
      var bOffset = chunk << 6;
      for (var i = 0; i < 16; i++) {
        var o = bOffset + (i << 2);
        a[72 + i] = ((b[o] & 0xff) << 24) | ((b[o + 1] & 0xff) << 16) | ((b[o + 2] & 0xff) << 8) | (b[o + 3] & 0xff);
      }
      for (var i = 16; i < 64; i++) {
        var wim15 = a[72 + i - 15];
        var s0 = ((wim15 >>> 7) | (wim15 << 25)) ^ ((wim15 >>> 18) | (wim15 << 14)) ^ (wim15 >>> 3);
        var wim2 = a[72 + i - 2];
        var s1 = ((wim2 >>> 17) | (wim2 << 15)) ^ ((wim2 >>> 19) | (wim2 << 13)) ^ (wim2 >>> 10);
        a[72 + i] = a[72 + i - 16] + s0 + a[72 + i - 7] + s1;
      }
      var A = a[64];
      var B = a[65];
      var C = a[66];
      var D = a[67];
      var E = a[68];
      var F = a[69];
      var G = a[70];
      var H = a[71];
      for (var i = 0; i < 64; i++) {
        var s1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7));
        var ch = (E & F) ^ ((~E) & G);
        var temp1 = H + s1 + ch + a[i] + a[72 + i];
        var s0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10));
        var maj = (A & B) ^ (A & C) ^ (B & C);
        var temp2 = s0 + maj;
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
      }
      a[64] += A;
      a[65] += B;
      a[66] += C;
      a[67] += D;
      a[68] += E;
      a[69] += F;
      a[70] += G;
      a[71] += H;
    }
    var ret = new Uint8Array(32);
    for (var i = 0; i < 8; i++) {
      var ah = a[64 + i];
      ret[i * 4] = (ah >>> 24) & 0xff;
      ret[i * 4 + 1] = (ah >>> 16) & 0xff;
      ret[i * 4 + 2] = (ah >>> 8) & 0xff;
      ret[i * 4 + 3] = ah & 0xff;
    }
    return resolve(ret);
  });
};