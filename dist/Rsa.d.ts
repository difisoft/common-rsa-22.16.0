declare class Rsa {
    private usingOldRsa;
    private padding?;
    private rsaPublicKey;
    private rsaPrivateKey;
    private oldRsaPublic;
    private oldRsaPrivate;
    constructor(publicKeyPath: string, privateKeyPath: string, usingOldRsa?: boolean, padding?: number | undefined);
    rsaEncrypt: (data: string) => string;
    rsaEncryptShort: (data: string) => string;
    rsaDecrypt: (data: string) => string;
    rsaDecryptShort(data: string): string;
}
export default Rsa;
