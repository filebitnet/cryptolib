const {
  Expect,
  Test,
  TestFixture,
  SpyOn,
  Focus,
  Timeout
} = require("alsatian");
const {
  readOnly
} = require('./utils');
const {
  createHash
} = require('crypto');

global.self = this;
const CryptoLib = require('../crypto.js');

@TestFixture("CryotoLibTest")
class CryotoLibTest {

  // !!!!!!!!!!!!!!!!! ATTENTION, this is a unit test, !!!!!!!!!!!!!!!!!
  // NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER 
  // NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER NEVER 
  // use null keys/ivs, i hope i was clear enough on this.
  // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  @readOnly _key = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  @readOnly _iv = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  @readOnly mergedResult = Buffer.from([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  @readOnly mergedResult64 = 'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  @readOnly helloworld = Buffer.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]);
  @readOnly helloworld64 = 'SGVsbG8gV29ybGQ';
  @readOnly encrypted = Buffer.from([189, 101, 203, 77, 29, 80, 101, 153, 47, 203, 65, 151, 115, 237, 2, 240]);

  @Test("test_lib validity")
  async test_lib() {
    // base functions
    Expect(CryptoLib.crypto).toBeDefined();
    Expect(CryptoLib.sha256).toBeDefined();
    Expect(CryptoLib.hex).toBeDefined();
    Expect(CryptoLib.base64).toBeDefined();
    Expect(CryptoLib.crypto).toBeDefined();
    Expect(CryptoLib.utils).toBeDefined();

    // crypto functions
    Expect(CryptoLib.crypto.encrypt).toBeDefined();
    Expect(CryptoLib.crypto.decrypt).toBeDefined();
    Expect(CryptoLib.crypto.mergeKeyIv).toBeDefined();
    Expect(CryptoLib.crypto.unmergeKeyIv).toBeDefined();

    // base64 functions
    Expect(CryptoLib.base64.encode).toBeDefined();
    Expect(CryptoLib.base64.decode).toBeDefined();


    //util functions
    Expect(CryptoLib.utils.uint8_to_hex).toBeDefined();
    Expect(CryptoLib.utils.str_to_uint8).toBeDefined();
    Expect(CryptoLib.utils.uint8_to_str).toBeDefined();
    Expect(CryptoLib.utils.is_ab).toBeDefined();
    Expect(CryptoLib.utils.assert_ab).toBeDefined();
    Expect(CryptoLib.utils.is_str).toBeDefined();
    Expect(CryptoLib.utils.assert_str).toBeDefined();
    Expect(CryptoLib.utils.is_uint8).toBeDefined();
    Expect(CryptoLib.utils.assert_uint8).toBeDefined();
    Expect(CryptoLib.utils.is_buf).toBeDefined();
    Expect(CryptoLib.utils.assert_buf).toBeDefined();
    Expect(CryptoLib.utils.is_undef).toBeDefined();
    Expect(CryptoLib.utils.assert_undef).toBeDefined();
  }

  @Test("test_lib validity")
  async test_encryption() {
    let encrypt = await CryptoLib.crypto.encrypt(this.helloworld, this._key, this._iv);

    Expect(Buffer.compare(encrypt, this.encrypted)).toBe(0); // 0 = they are equal
  }

  @Test("random encryption")
  async test_random_encryption() {
    const randomText = String("test-encrypt-" + new Date().toUTCString());
    let text = createHash('sha256').update(randomText).digest('hex');

    const key = CryptoLib.keygen();
    const iv = CryptoLib.keygen();

    Expect(key.byteLength).toBe(16);
    Expect(iv.byteLength).toBe(16);

    const encrypted = await CryptoLib.crypto.encrypt(Buffer.from(text), key, iv);

    Expect(encrypted instanceof Buffer).toBeTruthy();

    const decrypted = await CryptoLib.crypto.decrypt(encrypted, key, iv);

    Expect(decrypted instanceof Buffer).toBeTruthy();
    Expect(decrypted.toString()).toBe(text);
  }

  @Test("base64")
  async test_base64() {

    //Expect(CryptoLib.base64.encode("invalid input")).toThrowError();
    //Expect(CryptoLib.base64.decode(Buffer.from([0, 0]))).toThrowError();

    const base64_result = CryptoLib.base64.encode(this.helloworld);
    Expect(base64_result).toBe(this.helloworld64);

    const base64_decoded = CryptoLib.base64.decode(this.helloworld64);
    Expect(Buffer.compare(base64_decoded, this.helloworld)).toBe(0);

    const randomText = String("test-encrypt-" + new Date().toUTCString());
    const base64_result_2 = CryptoLib.base64.encode(Buffer.from(randomText));

    Expect(CryptoLib.utils.is_str(base64_result_2)).toBeTruthy();

    const base64_decoded_2 = CryptoLib.base64.decode(base64_result_2);
    Expect(base64_decoded_2 instanceof Buffer).toBeTruthy();
    Expect(base64_decoded_2.toString()).toBe(randomText);
  }

  @Test("merge and unmerge keys")
  async test_merge() {
    const merged = CryptoLib.crypto.mergeKeyIv(this._key, this._iv);
    Expect(Buffer.compare(merged, this.mergedResult)).toBe(0);

    const base64 = CryptoLib.base64.encode(merged);
    Expect(base64).toBe(this.mergedResult64);

    const unmerged = CryptoLib.crypto.unmergeKeyIv(merged);

    Expect(Buffer.compare(unmerged.version, Buffer.from([1]))).toBe(0)
    Expect(Buffer.compare(unmerged.key, this._key)).toBe(0);
    Expect(Buffer.compare(unmerged.iv, this._iv)).toBe(0);
  }

}

module.exports = CryotoLibTest;