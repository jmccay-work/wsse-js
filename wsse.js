//
// wsse.js - Generate WSSE authentication header in JavaScript
// (C) 2005 Victor R. Ruiz <victor*sixapart.com> - http://rvr.typepad.com/
//
// Parts:
//   SHA-1 library (C) 2000-2002 Paul Johnston - BSD license
//   ISO 8601 function (C) 2000 JF Walker All Rights
//   Base64 function (C) aardwulf systems - Creative Commons
//
// Example call:
//
//   let w = wsseHeader(Username, Password);
//   alert('X-WSSE: ' + w);
//
// Changelog:
//   2005.07.21 - Release 1.0
//   2022.03.11 - JLM Updated for ES6 and use strict

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

"use strict";

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
let hexcase = 0; /* hex output format. 0 - lowercase; 1 - uppercase        */
let b64pad = "="; /* base-64 pad character. "=" for strict RFC compliance   */
let chrsz = 8; /* bits per input character. 8 - ASCII; 16 - Unicode      */

const VALID_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
const hex_sha1 = (s_) => {
    return binb2hex(core_sha1(str2binb(s_), s_.length * chrsz));
};
const b64_sha1 = (s_) => {
    return binb2b64(core_sha1(str2binb(s_), s_.length * chrsz));
};
const str_sha1 = (s_) => {
    return binb2str(core_sha1(str2binb(s_), s_.length * chrsz));
};
const hex_hmac_sha1 = (key_, data_) => {
    return binb2hex(core_hmac_sha1(key_, data_));
};
const b64_hmac_sha1 = (key_, data_) => {
    return binb2b64(core_hmac_sha1(key_, data_));
};
const str_hmac_sha1 = (key_, data_) => {
    return binb2str(core_hmac_sha1(key_, data_));
};

/*
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test() {
    return hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x_, len_) {
    /* append padding */
    x_[len_ >> 5] |= 0x80 << (24 - (len_ % 32));
    x_[(((len_ + 64) >> 9) << 4) + 15] = len_;

    let w = Array(80);
    let a = 1732584193;
    let b = -271733879;
    let c = -1732584194;
    let d = 271733878;
    let e = -1009589776;

    for (let i = 0; i < x_.length; i += 16) {
        let olda = a;
        let oldb = b;
        let oldc = c;
        let oldd = d;
        let olde = e;

        for (let j = 0; j < 80; j++) {
            if (j < 16) w[j] = x_[i + j];
            else w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            let t = safe_add(
                safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                safe_add(safe_add(e, w[j]), sha1_kt(j))
            );
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        }

        a = safe_add(a, olda);
        b = safe_add(b, oldb);
        c = safe_add(c, oldc);
        d = safe_add(d, oldd);
        e = safe_add(e, olde);
    }
    return Array(a, b, c, d, e);
}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t_, b_, c_, d_) {
    if (t_ < 20) return (b_ & c_) | (~b_ & d_);
    if (t_ < 40) return b_ ^ c_ ^ d_;
    if (t_ < 60) return (b_ & c_) | (b_ & d_) | (c_ & d_);
    return b_ ^ c_ ^ d_;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t_) {
    return t_ < 20
        ? 1518500249
        : t_ < 40
        ? 1859775393
        : t_ < 60
        ? -1894007588
        : -899497514;
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key_, data_) {
    let bkey = str2binb(key_);
    if (bkey.length > 16) bkey = core_sha1(bkey, key_.length * chrsz);

    let ipad = Array(16),
        opad = Array(16);
    for (let i = 0; i < 16; i++) {
        ipad[i] = bkey[i] ^ 0x36363636;
        opad[i] = bkey[i] ^ 0x5c5c5c5c;
    }

    let hash = core_sha1(
        ipad.concat(str2binb(data_)),
        512 + data.length * chrsz
    );
    return core_sha1(opad.concat(hash), 512 + 160);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x_, y_) {
    let lsw = (x_ & 0xffff) + (y_ & 0xffff);
    let msw = (x_ >> 16) + (y_ >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num_, cnt_) {
    return (num_ << cnt_) | (num_ >>> (32 - cnt_));
}

/*
 * Convert an 8-bit or 16-bit string to an array of big-endian words
 * In 8-bit function, characters >255 have their hi-byte silently ignored.
 */
function str2binb(str_) {
    let bin = Array();
    let mask = (1 << chrsz) - 1;
    for (let i = 0; i < str_.length * chrsz; i += chrsz)
        bin[i >> 5] |=
            (str_.charCodeAt(i / chrsz) & mask) << (32 - chrsz - (i % 32));
    return bin;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2str(bin_) {
    let str = "";
    let mask = (1 << chrsz) - 1;
    for (let i = 0; i < bin_.length * 32; i += chrsz)
        str += String.fromCharCode(
            (bin_[i >> 5] >>> (32 - chrsz - (i % 32))) & mask
        );
    return str;
}

/*
 * Convert an array of big-endian words to a hex string.
 */
function binb2hex(binarray_) {
    let hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    let str = "";
    for (let i = 0; i < binarray_.length * 4; i++) {
        str +=
            hex_tab.charAt(
                (binarray_[i >> 2] >> ((3 - (i % 4)) * 8 + 4)) & 0xf
            ) +
            hex_tab.charAt((binarray_[i >> 2] >> ((3 - (i % 4)) * 8)) & 0xf);
    }
    return str;
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function binb2b64(binarray_) {
    //  let tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let tab = VALID_CHARS;
    let str = "";
    for (let i = 0; i < binarray_.length * 4; i += 3) {
        let triplet =
            (((binarray_[i >> 2] >> (8 * (3 - (i % 4)))) & 0xff) << 16) |
            (((binarray_[(i + 1) >> 2] >> (8 * (3 - ((i + 1) % 4)))) & 0xff) <<
                8) |
            ((binarray_[(i + 2) >> 2] >> (8 * (3 - ((i + 2) % 4)))) & 0xff);
        for (let j = 0; j < 4; j++) {
            if (i * 8 + j * 6 > binarray_.length * 32) str += b64pad;
            else str += tab.charAt((triplet >> (6 * (3 - j))) & 0x3f);
        }
    }
    return str;
}

// aardwulf systems
// This work is licensed under a Creative Commons License.
// http://www.aardwulf.com/tutor/base64/
function encode64(input_) {
    let keyStr = `${VALID_CHARS}=`;
    /* 
    let keyStr = "ABCDEFGHIJKLMNOP" +
                "QRSTUVWXYZabcdef" +
                "ghijklmnopqrstuv" +
                "wxyz0123456789+/" +
                "=";
*/

    let output = "";
    let chr1,
        chr2,
        chr3 = "";
    let enc1,
        enc2,
        enc3,
        enc4 = "";
    let i = 0;

    do {
        chr1 = input_.charCodeAt(i++);
        chr2 = input_.charCodeAt(i++);
        chr3 = input_.charCodeAt(i++);

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }

        output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4);
        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";
    } while (i < input_.length);

    return output;
}

// TITLE
// TempersFewGit v 2.1 (ISO 8601 Time/Date script)
//
// OBJECTIVE
// Javascript script to detect the time zone where a browser
// is and display the date and time in accordance with the
// ISO 8601 standard.
//
// AUTHOR
// John Walker
// http://321WebLiftOff.net
// jfwalker@ureach.com
//
// ENCOMIUM
// Thanks to Stephen Pugh for his help.
//
// CREATED
// 2000-09-15T09:42:53+01:00
//
// UPDATED
// 2022-03-11 JLM Updated to ES6 and to use less strings.
//
// REFERENCES
// For more about ISO 8601 see:
// http://www.w3.org/TR/NOTE-datetime
// http://www.cl.cam.ac.uk/~mgk25/iso-time.html
//
// COPYRIGHT
// This script is Copyright  2000 JF Walker All Rights
// Reserved but may be freely used provided this colophon is
// included in full.
//
function isodatetime() {
    let today = new Date();
    let year = today.getFullYear();
    if (year < 2000) {
        // this should not be needed now
        // Y2K Fix, Isaac Powell
        year = year + 1900; // http://onyx.idbsu.edu/~ipowell
    }
    let month = today.getMonth() + 1;
    let day = today.getDate();
    let hour = today.getHours();
    let hourUTC = today.getUTCHours();
    let diff = hour - hourUTC;
    if (diff > 12) diff -= 24; // Fix the problem for town with real negative diff
    if (diff <= -12) diff += 24; // Fix the problem for town with real positive diff
    let hourdifference = Math.abs(diff);
    let minute = today.getMinutes();
    let minuteUTC = today.getUTCMinutes();
    let minutedifference;
    let second = today.getSeconds();
    let timezone;
    if (minute != minuteUTC && minuteUTC < 30 && diff < 0) {
        hourdifference--;
    }
    if (minute != minuteUTC && minuteUTC > 30 && diff > 0) {
        hourdifference--;
    }
    minutedifference = (minute != minuteUTC)? ":30" : ":00";
    timezone = `${diff < 0 ? "-" : "+"}${(hourdifference < 10)?"0":""}${hourdifference}${minutedifference}`;
    if (month <= 9) month = `0${month}`; //"0" + month;
    if (day <= 9) day = `0${day}`; //"0" + day;
    if (hour <= 9) hour = `0${hour}`; //"0" + hour;
    if (minute <= 9) minute = `0${minute}`; //"0" + minute;
    if (second <= 9) second = `0${second}`; //"0" + second;
    let time = `${year}-${month}-${day}T${hour}:${minute}:${second}${timezone}`;
    return time;
}

// (C) 2005 Victor R. Ruiz <victor*sixapart.com>
// Code to generate WSSE authentication header
//
// http://www.sixapart.com/pronet/docs/typepad_atom_api
//
// X-WSSE: UsernameToken Username="name", PasswordDigest="digest", Created="timestamp", Nonce="nonce"
//
//  * Username- The username that the user enters (the TypePad username).
//  * Nonce. A secure token generated anew for each HTTP request.
//  * Created. The ISO-8601 timestamp marking when Nonce was created.
//  * PasswordDigest. A SHA-1 digest of the Nonce, Created timestamp, and the password
//    that the user supplies, base64-encoded. In other words, this should be calculated
//    as: base64(sha1(Nonce . Created . Password))
//

function wsse(password_) {
    let passwordDigest, nonce, created;
    let r = new Array();

    //    Nonce = b64_sha1(isodatetime() + 'There is more than words');
    let t = `${isodatetime()}There is more than words${( Date.now() )}`;
    nonce = b64_sha1(t);
    let nonceEncoded = encode64(nonce);
    created = isodatetime();
    passwordDigest = b64_sha1(nonce + created + password_);

    r[0] = nonceEncoded;
    r[1] = created;
    r[2] = passwordDigest;
    return r;
}

function wsseHeader(username_, password_) {
    let w = wsse(password_);
    //    let header = 'UsernameToken Username="' + Username + '", PasswordDigest="' + w[2] + '", Created="' + w[1] + '", Nonce="' + w[0] + '"';
    let header = `UsernameToken Username="${username_}", PasswordDigest="${w[2]}", Created="${w[1]}", Nonce="${w[0]}"`;
    return header;
}
