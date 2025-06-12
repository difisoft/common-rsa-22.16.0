import fs from 'fs';
import { publicEncrypt, privateDecrypt } from 'crypto';

const MULTI_ENCRYPTION_PART_PREFIX = 'mutipart';

class Rsa {

  private rsaPublicKey: string;
  private rsaPrivateKey: string;

  constructor(
    publicKeyPath: string,
    privateKeyPath: string,
  ) {
    this.rsaPublicKey = fs.readFileSync(publicKeyPath, 'utf8');
    this.rsaPrivateKey = fs.readFileSync(privateKeyPath, 'utf8');
  }

  public rsaEncrypt = (data: string) => {
    try {
      return this.rsaEncryptShort(data);
    } catch (e: any) {
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
  }

  public rsaEncryptShort = (data: string) => {
    const buffer = Buffer.from(data);
    const encrypted = publicEncrypt({ key: this.rsaPublicKey, padding: 1 }, buffer);
    return encrypted.toString("base64");
  };

  public rsaDecrypt = (data: string) => {
    if (data.startsWith(`${MULTI_ENCRYPTION_PART_PREFIX}.`)) {
      const parts = data.split(".");
      let result = "";
      for (let i = 1; i < parts.length; i++) {
        result += this.rsaDecryptShort(parts[i]);
      }
      return result;
    } else {
      return this.rsaDecryptShort(data);
    }
  }

  public rsaDecryptShort(data: string) {
    const buffer = Buffer.from(data, "base64");
    const decrypted = privateDecrypt({ key: this.rsaPrivateKey, padding: 1 }, buffer);
    return decrypted.toString("utf8");
  };
}

export default Rsa;