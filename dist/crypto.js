var filebitCrypto;
filebitCrypto = (() => {
  var t = {
      979: (t, e, r) => {
        const {
          is_str: n,
          is_uint8: a,
          str_to_buffer: s,
          buffer_to_str: i,
          assert_uint8: o
        } = r(274);
        t.exports.encode = t => {
          return n(t) && (t = s(t)), e = function(t) {
            o(t, "uint8toBase64 input needs to be uint8array");
            for (var e = "", r = new Uint8Array(t), n = r.byteLength, a = 0; a < n; a++) e += String.fromCharCode(r[a]);
            return btoa(e)
          }(t), String(e).replace(/\+/gi, "-").replace(/\//gi, "_").replace(/=/gi, "");
          var e
        }, t.exports.decode = (t, e = !0) => (t = (t => String(t).replace(/\-/gi, "+").replace(/_/gi, "/"))(t), e ? function(t) {
          for (var e = atob(t), r = e.length, n = new Uint8Array(r), a = 0; a < r; a++) n[a] = e.charCodeAt(a);
          return n
        }(t) : atob(t))
      },
      502: (t, e, r) => {
        const n = r(274);
        t.exports.mergeKeyIv = (t, e) => {
          n.assert_uint8(t, "key is not an uint8array"), n.assert_uint8(e, "iv is not an uint8array");
          const r = t.byteLength + e.byteLength;
          let a = new ArrayBuffer(t.byteLength + e.byteLength + 1),
            s = new Uint8Array(a);
          const i = new DataView(t.buffer),
            o = new DataView(e.buffer);
          s[0] = 1;
          for (let t = 0; t < r; ++t) {
            let e = Math.floor(t / 2),
              r = t % 2 ? i.getUint8(e) : o.getUint8(e);
            s[t + 1] = r
          }
          return s
        }, t.exports.unmergeKeyIv = t => {
          if (n.assert_uint8(t, "buf is not an uint8array"), (t.byteLength - 1) % 2) throw new Error("unmergeKeyIv buf is invalid length is: " + t.byteLength);
          let e = new DataView(t.buffer);
          const r = e.getUint8(0),
            a = t.byteLength - 1,
            s = new Uint8Array(a / 2),
            i = new Uint8Array(a / 2);
          for (let t = 0; t < a; ++t) {
            let r = e.getUint8(1 + t),
              n = Math.floor(t / 2);
            t % 2 ? s[n] = r : i[n] = r
          }
          return {
            version: r,
            key: s,
            iv: i
          }
        }
      },
      500: (t, e, r) => {
        const {
          mergeKeyIv: n,
          unmergeKeyIv: a
        } = r(502), s = r(979), i = r(274), o = r(65);
        t.exports.unmergeKeyIv = a, t.exports.mergeKeyIv = n, t.exports.nameKeySizeHash = async(t, e, r) => {
          i.assert_undef(t, "name is undefined"), i.assert_undef(e, "size is undefined"), i.assert_undef(r, "key is undefined"), i.assert_uint8(r, "key is not an uint8array"), i.assert_str(t, "name is not a string");
          const n = s.encode(r),
            a = await o(i.str_to_uint8(n + t + n)),
            u = `{n:${t}:s${e}:k${n}}`,
            y = await o(i.str_to_uint8(u + i.uint8_to_hex(a, !0)));
          return i.uint8_to_hex(y, !0)
        }, t.exports.encrypt = (t, e, r) => new Promise((async n => {
          i.assert_uint8(t, "data needs to be an uint8array"), i.assert_uint8(e, "key needs to be an uint8array"), i.assert_uint8(r, "iv needs to be an uint8array");
          let a = await crypto.subtle.importKey("raw", new Uint8Array(e), {
              name: "AES-CBC"
            }, !1, ["encrypt"]),
            s = await crypto.subtle.encrypt({
              name: "AES-CBC",
              iv: new Uint8Array(r)
            }, a, t);
          n(new Uint8Array(s))
        })), t.exports.decrypt = (t, e, r) => new Promise((async n => {
          i.assert_uint8(t, "data needs to be an uint8array"), i.assert_uint8(e, "key needs to be an uint8array"), i.assert_uint8(r, "iv needs to be an uint8array"), t = new Uint8Array(t), e = new Uint8Array(e), r = new Uint8Array(r);
          let a = await crypto.subtle.importKey("raw", new Uint8Array(e), {
              name: "AES-CBC"
            }, !1, ["decrypt"]),
            s = await crypto.subtle.decrypt({
              name: "AES-CBC",
              iv: r
            }, a, new Uint8Array(t));
          n(new Uint8Array(s))
        }))
      },
      217: t => {
        var e = function(t, e) {
          for (t = t.toString(16).toUpperCase(); t.length < e;) t = "0" + t;
          return t
        };
        t.exports = function(t) {
          var r = Math.ceil(t.length / 16),
            n = t.length % 16 || 16,
            a = t.length.toString(16).length;
          a < 6 && (a = 6);
          for (var s, i = "Offset"; i.length < a;) i += " ";
          for (i = "[36m" + i + "  ", s = 0; s < 16; s++) i += " " + e(s, 2);
          i += "[0m\n", t.length && (i += "\n");
          var o, u, y, f = 0;
          for (s = 0; s < r; s++) {
            var p;
            for (i += "[36m" + e(f, a) + "[0m  ", u = 16 - (o = s === r - 1 ? n : 16), p = 0; p < o; p++) i += " " + e(t[f], 2), f++;
            for (p = 0; p < u; p++) i += "   ";
            for (f -= o, i += "   ", p = 0; p < o; p++) i += (y = t[f]) > 31 && y < 127 || y > 159 ? String.fromCharCode(y) : ".", f++;
            i += "\n"
          }
          console.log(i)
        }
      },
      751: t => {
        t.exports = (t = 128) => {
          let e = t / 8,
            r = new ArrayBuffer(e),
            n = new Uint8Array(r),
            a = new Uint8Array(e);
          window.crypto.getRandomValues(a);
          for (let t = 0; t <= a.length; ++t) n[t] = a[t];
          return n
        }
      },
      65: (t, e, r) => {
        const n = r(274);
        t.exports = function(t) {
          return new Promise((async e => {
            n.assert_uint8(t, "input for sha256 needs to be uint8array");
            let r = await crypto.subtle.digest("SHA-256", t);
            return e(new Uint8Array(r))
          }))
        }
      },
      274: t => {
        const e = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"],
          r = new Array(256);
        for (let t = 0; t < 256; t++) r[t] = `${e[t>>>4&15]}${e[15&t]}`;
        t.exports.uint8_to_hex = (t, e = !1) => {
          n(t) && (t = new Uint8Array(t));
          let a = "";
          for (let e = 0, n = t.length; e < n; e++) a += r[t[e]];
          return e ? a.toLowerCase() : a
        }, t.exports.str_to_uint8 = t => (new TextEncoder).encode(t), t.exports.uint8_to_str = t => (new TextDecoder).decode(t);
        const n = t.exports.is_ab = t => t instanceof ArrayBuffer;
        t.exports.assert_ab = (t, e = "input is not an arraybuffer") => {
          if (!n(t)) throw new Error(e)
        };
        const a = t.exports.is_str = t => "string" == typeof t;
        t.exports.assert_str = (t, e = "input is not an string") => {
          if (!a(t)) throw new Error(e)
        };
        const s = t.exports.is_uint8 = t => t instanceof Uint8Array;
        t.exports.assert_uint8 = (t, e = "input is not an uint8array") => {
          if (!s(t)) throw new Error(e)
        };
        const i = t.exports.is_undef = t => void 0 === t;
        t.exports.assert_undef = (t, e = "input is undefined") => {
          if (i(t)) throw new Error(e)
        }
      },
      814: (t, e, r) => {
        t.exports.keygen = r(751), t.exports.sha256 = r(65), t.exports.hex = r(217), t.exports.base64 = r(979), t.exports.crypto = r(500), t.exports.utils = r(274)
      }
    },
    e = {};
  return function r(n) {
    if (e[n]) return e[n].exports;
    var a = e[n] = {
      exports: {}
    };
    return t[n](a, a.exports, r), a.exports
  }(814)
})();