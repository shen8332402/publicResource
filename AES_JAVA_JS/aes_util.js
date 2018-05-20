import CryptoJS from 'crypto-js';
const key = CryptoJS.enc.Latin1.parse('1234123412ABCDEF');
const iv = CryptoJS.enc.Latin1.parse('ABCDEF1234123412');
const mode = CryptoJS.mode.CBC;
const padding = CryptoJS.pad.ZeroPadding;

function encryptData(data){
  //加密
  let encrypted = CryptoJS.AES.encrypt(
    data,
    key,
    {
      iv: iv, mode: mode, padding: padding
    });
  //console.log('encrypted: ' + encrypted);
  return encrypted;
}

function decryptData(data){
  //解密
  let decrypted = CryptoJS.AES.decrypt(data, key, { iv: iv, padding: padding });
  //console.log('decrypted: ' + decrypted.toString(CryptoJS.enc.Utf8));
  return decrypted;
}

module.exports = { decryptData: decryptData,
  encryptData: encryptData
} 
