// general functions

var blake = require('blakejs');
var nanoBase32 = require('nano-base32')

export const stringFromHex = function(hex) {
  var hex = hex.toString();//force conversion
  var str = '';
  for (var i = 0; i < hex.length; i += 2)
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return str;
}

export const stringToHex = function (str) {
  var hex = '';
  for (var i = 0; i < str.length; i++) {
    hex += '' + str.charCodeAt(i).toString(16);
  }
  return hex;
}

export const accountFromHexKey = function (hex) {
  var key_bytes = hex_uint8(hex)
  var checksum_bytes = blake.blake2b(key_bytes, null, 5).reverse();
  var checksum = nanoBase32.encode(checksum_bytes);
  var c_account = nanoBase32.encode(key_bytes);
  return 'xrb_' + c_account + checksum;
};

export const parseXRBAccount = function(str) {
  var i = str.indexOf('xrb_');
  var acc = false;
  if (i != -1)
    acc = str.slice(i, i + 64);
  else
    i = str.indexOf('nano_');

  if (i != -1) {
    if(!acc)
      acc = str.slice(i, i + 65);
    try {
      keyFromAccount(acc);
      return acc;
    } catch (e) {
      return false;
    }
  }
  return false;
}


export const dec2hex = function (str, bytes = null) {
  var dec = str.toString().split(''), sum = [], hex = [], i, s
  while (dec.length) {
    s = 1 * dec.shift()
    for (i = 0; s || i < sum.length; i++) {
      s += (sum[i] || 0) * 10
      sum[i] = s % 16
      s = (s - sum[i]) / 16
    }
  }
  while (sum.length) {
    hex.push(sum.pop().toString(16));
  }

  hex = hex.join('');

  if (hex.length % 2 != 0)
    hex = "0" + hex;

  if (bytes > hex.length / 2) {
    var diff = bytes - hex.length / 2;
    for (var i = 0; i < diff; i++)
      hex = "00" + hex;
  }

  return hex;
}

export const hex2dec = function(s) {

  function add(x, y) {
    var c = 0, r = [];
    var x = x.split('').map(Number);
    var y = y.split('').map(Number);
    while (x.length || y.length) {
      var s = (x.pop() || 0) + (y.pop() || 0) + c;
      r.unshift(s < 10 ? s : s - 10);
      c = s < 10 ? 0 : 1;
    }
    if (c) r.unshift(c);
    return r.join('');
  }

  var dec = '0';
  s.split('').forEach(function (chr) {
    var n = parseInt(chr, 16);
    for (var t = 8; t; t >>= 1) {
      dec = add(dec, dec);
      if (n & t) dec = add(dec, '1');
    }
  });
  return dec;
}

export const hex_uint8 = function (hex) {
  var length = (hex.length / 2) | 0;
  var uint8 = new Uint8Array(length);
  for (let i = 0; i < length; i++) uint8[i] = parseInt(hex.substr(i * 2, 2), 16);
  return uint8;
}

export const uint8_hex = function (uint8) {
  var hex = "";
  let aux;
  for (let i = 0; i < uint8.length; i++) {
    aux = uint8[i].toString(16).toUpperCase();
    if (aux.length == 1)
      aux = '0' + aux;
    hex += aux;
    aux = '';
  }
  return (hex);
}

export const uint4_hex = function (uint4) {
  var hex = "";
  for (let i = 0; i < uint4.length; i++) hex += uint4[i].toString(16).toUpperCase();
  return (hex);
}

function equal_arrays(array1, array2) {
  for (let i = 0; i < array1.length; i++) {
    if (array1[i] != array2[i])  return false;
  }
  return true;
}

export const keyFromAccount = function(account) {
  if ( ( (account.startsWith('xrb_1') || account.startsWith('xrb_3')) && (account.length == 64) )
  || ( (account.startsWith('nano_1') || account.startsWith('nano_3')) && (account.length == 65) ) ) {
    var account_crop = account.replace('xrb_', '').replace('nano_', '');
    var isValid = /^[13456789abcdefghijkmnopqrstuwxyz]+$/.test(account_crop);
    if (isValid) {
      var key_bytes = nanoBase32.decode(account_crop.substring(0, 52));
      var hash_bytes = nanoBase32.decode(account_crop.substring(52, 60));
      var blake_hash = blake.blake2b(key_bytes, null, 5).reverse();
      if (equal_arrays(hash_bytes, blake_hash)) {
        var key = uint8_hex(key_bytes).toUpperCase();
        return key;
      }
      else
        throw "Checksum incorrect.";
    }
    else
      throw "Invalid XRB account.";
  }
  throw "Invalid XRB account.";
}