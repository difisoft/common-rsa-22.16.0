declare class Rsa {
    private usingOldRsa;
    private rsaPublicKey;
    private rsaPrivateKey;
    private oldRsaPublic;
    private oldRsaPrivate;
    constructor(publicKeyPath: string, privateKeyPath: string, usingOldRsa?: boolean);
    rsaEncrypt: (data: string) => string;
    rsaEncryptShort: (data: string) => string;
    rsaDecrypt: (data: string) => string;
    rsaDecryptShort(data: string): string;
}
export default Rsa;
