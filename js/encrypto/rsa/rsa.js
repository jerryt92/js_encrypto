import JSEncrypt from 'jsencrypt';
import CryptoJS from "crypto-js";

const signEncryptAlgorithm = "sha256";

// keySize: 1024, 2048, 4096
// RSA公私钥对生成
export function generateKey(keySize) {
	let crypt = new JSEncrypt({default_key_size: keySize});
	new Promise(function (resolve) {
		setTimeout(function () {
			resolve([crypt.getPrivateKey(), crypt.getPublicKey()]);
		}, 50);
	}).then(function (e) {
		// area_private_key: e[0], area_public_key: e[1]
		return e;
	});
}

// RSA加密
export function rsaEncrypt(publicKey, data) {
	var jsEncrypt = new JSEncrypt();
	if (data.length > 0 && publicKey.length > 0) {
		jsEncrypt.setPublicKey(publicKey);
		let encrypted = jsEncrypt.encrypt(data);
		if (encrypted == false) {
			throw new Error("Encrypt failed");
		} else {
			return encrypted;
		}
	}
	return "";
}

// RSA解密
export function rsaDecrypt(privateKey, encrypted) {
	var jsEncrypt = new JSEncrypt();
	jsEncrypt.setPrivateKey(privateKey);
	let decrypted = jsEncrypt.decrypt(encrypted);
	if (decrypted == false || decrypted == null) {
		throw new Error("Decrypt failed");
	} else {
		return decrypted;
	}
}

// RSA签名
export function rsaSign(privateKey, data) {
	var jsEncrypt = new JSEncrypt();
	jsEncrypt.setPrivateKey(privateKey);
	let signature;
	if (signEncryptAlgorithm == "sha1") {
		signature = jsEncrypt.sign(data, CryptoJS.SHA1, "sha1");
	}
	if (signEncryptAlgorithm == "sha256") {
		signature = jsEncrypt.sign(data, CryptoJS.SHA1, "sha256");
	}
	if (signEncryptAlgorithm == "sha512") {
		signature = jsEncrypt.sign(data, CryptoJS.SHA1, "sha512");
	}
	if (signature == false) {
		throw new Error("Sign failed");
	} else {
		return signature;
	}
}

// RSA验签
function verifySignature(publicKey, privateKey, data, signature) {
	var jsEncrypt = new JSEncrypt();
	jsEncrypt.setPublicKey(publicKey);
	jsEncrypt.setPrivateKey(privateKey);
	var verified = false;
	if (signEncryptAlgorithm == "sha1") {
		verified = jsEncrypt.verify(data, signature, CryptoJS.SHA1);
	}
	if (signEncryptAlgorithm == "sha256") {
		verified = jsEncrypt.verify(data, signature, CryptoJS.SHA256);
	}
	if (signEncryptAlgorithm == "sha512") {
		verified = jsEncrypt.verify(data, signature, CryptoJS.SHA512);
	}
	return verified;
}
