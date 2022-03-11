/**
 * base64.js
 * Original author: Chris Veness
 * Repository: https://gist.github.com/chrisveness/e121cffb51481bd1c142
 * License: MIT (According to a comment).
 * 
 * 03/09/2022 JLM Updated to ES6 and strict. 
 */

/**
 * Encode string into Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648].
 * As per RFC 4648, no newlines are added.
 *
 * Characters in str must be within ISO-8859-1 with Unicode code point <= 256.
 *
 * Can be achieved JavaScript with btoa(), but this approach may be useful in other languages.
 *
 * @param {string} str_ ASCII/ISO-8859-1 string to be encoded as base-64.
 * @returns {string} Base64-encoded string.
 */
 'use strict'

 const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
 
 //function base64Encode(str) {
 const base64Encode = (str_) => {
         if (/([^\u0000-\u00ff])/.test(str_)) throw Error('String must be ASCII');
 
     let b64 = B64_CHARS;
     let o1, o2, o3, bits, h1, h2, h3, h4, e=[], pad = '', c;
 
     c = str.length % 3;  // pad string to length of multiple of 3
     if (c > 0) { while (c++ < 3) { pad += '='; str_ += '\0'; } }
     // note: doing padding here saves us doing special-case packing for trailing 1 or 2 chars
 
     for (c=0; c<str_.length; c+=3) {  // pack three octets into four hexets
         o1 = str_.charCodeAt(c);
         o2 = str_.charCodeAt(c+1);
         o3 = str_.charCodeAt(c+2);
 
         bits = o1<<16 | o2<<8 | o3;
 
         h1 = bits>>18 & 0x3f;
         h2 = bits>>12 & 0x3f;
         h3 = bits>>6 & 0x3f;
         h4 = bits & 0x3f;
 
         // use hextets to index into code string
         e[c/3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
     }
     str_ = e.join('');  // use Array.join() for better performance than repeated string appends
 
     // replace 'A's from padded nulls with '='s
     str_ = str_.slice(0, str_.length-pad.length) + pad;
 
     return str_;
 }
 
 /**
  * Decode string from Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648].
  * As per RFC 4648, newlines are not catered for.
  *
  * Can be achieved JavaScript with atob(), but this approach may be useful in other languages.
  *
  * @param {string} str_ Base64-encoded string.
  * @returns {string} Decoded ASCII/ISO-8859-1 string.
  */
 //function Base64Decode(str) {
 const base64Decode = (str_) => {
         if (!(/^[a-z0-9+/]+={0,2}$/i.test(str_)) || str_.length%4 != 0) throw Error('Not base64 string');
 
     let b64 = B64_CHARS;
     let o1, o2, o3, h1, h2, h3, h4, bits, d=[];
 
     for (let c=0; c<str_.length; c+=4) {  // unpack four hexets into three octets
         h1 = b64.indexOf(str_.charAt(c));
         h2 = b64.indexOf(str_.charAt(c+1));
         h3 = b64.indexOf(str_.charAt(c+2));
         h4 = b64.indexOf(str_.charAt(c+3));
 
         bits = h1<<18 | h2<<12 | h3<<6 | h4;
 
         o1 = bits>>>16 & 0xff;
         o2 = bits>>>8 & 0xff;
         o3 = bits & 0xff;
 
         d[c/4] = String.fromCharCode(o1, o2, o3);
         // check for padding
         if (h4 == 0x40) d[c/4] = String.fromCharCode(o1, o2);
         if (h3 == 0x40) d[c/4] = String.fromCharCode(o1);
     }
     str_ = d.join('');  // use Array.join() for better performance than repeated string appends
 
     return str_;
 }