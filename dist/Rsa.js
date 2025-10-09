"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = __importDefault(require("fs"));
const crypto_1 = require("crypto");
const node_rsa_1 = __importDefault(require("node-rsa"));
const node_crypto_1 = require("node:crypto");
const MULTI_ENCRYPTION_PART_PREFIX = 'mutipart';
class Rsa {
    constructor(publicKeyPath, privateKeyPath, usingOldRsa = false, padding) {
        this.usingOldRsa = usingOldRsa;
        this.padding = padding;
        this.rsaEncrypt = (data) => {
            try {
                return this.rsaEncryptShort(data);
            }
            catch (e) {
                if (e.message != null && e.message.indexOf('data too large for key size') >= 0) {
                    let encryption = MULTI_ENCRYPTION_PART_PREFIX;
                    let index = 0;
                    while (index < data.length) {
                        const part = data.substr(index, Math.min(100, data.length - index));
                        encryption += `.${this.rsaEncryptShort(part)}`;
                        index += 100;
                    }
                    return encryption;
                }
                throw e;
            }
        };
        this.rsaEncryptShort = (data) => {
            if (this.usingOldRsa) {
                return this.oldRsaPublic.encrypt(data, 'base64');
            }
            const buffer = Buffer.from(data);
            const encrypted = (0, crypto_1.publicEncrypt)({
                key: this.rsaPublicKey,
                padding: this.padding
            }, buffer);
            return encrypted.toString("base64");
        };
        this.rsaDecrypt = (data) => {
            if (data.startsWith(`${MULTI_ENCRYPTION_PART_PREFIX}.`)) {
                const parts = data.split(".");
                let result = "";
                for (let i = 1; i < parts.length; i++) {
                    result += this.rsaDecryptShort(parts[i]);
                }
                return result;
            }
            else {
                return this.rsaDecryptShort(data);
            }
        };
        this.rsaPublicKey = fs_1.default.readFileSync(publicKeyPath, 'utf8');
        this.rsaPrivateKey = fs_1.default.readFileSync(privateKeyPath, 'utf8');
        if (this.usingOldRsa) {
            this.oldRsaPublic = new node_rsa_1.default(this.rsaPublicKey, 'public', {
                encryptionScheme: 'pkcs1',
            });
            this.oldRsaPublic.setOptions({
                environment: 'browser',
                encryptionScheme: 'pkcs1',
                signingScheme: 'pkcs1'
            });
            this.oldRsaPrivate = new node_rsa_1.default(this.rsaPrivateKey, 'private', {
                encryptionScheme: 'pkcs1',
            });
            this.oldRsaPrivate.setOptions({
                environment: 'browser',
                encryptionScheme: 'pkcs1',
                signingScheme: 'pkcs1'
            });
        }
        if (this.padding == null) {
            let envPadding = process.env.TRADEX_ENV_RSA_PADDING;
            if (envPadding != null) {
                try {
                    this.padding = parseInt(envPadding);
                }
                catch (e) {
                    this.padding = crypto_1.constants.RSA_PKCS1_OAEP_PADDING;
                }
            }
            if (this.padding == null) {
                this.padding = crypto_1.constants.RSA_PKCS1_OAEP_PADDING;
            }
        }
    }
    rsaDecryptShort(data) {
        if (this.usingOldRsa) {
            return this.oldRsaPrivate.decrypt(data, 'utf8');
        }
        const buffer = Buffer.from(data, 'base64');
        const decrypted = (0, node_crypto_1.privateDecrypt)({
            key: this.rsaPrivateKey,
            padding: this.padding
        }, buffer);
        return decrypted.toString('utf8');
    }
    ;
}
exports.default = Rsa;
//# sourceMappingURL=Rsa.js.map