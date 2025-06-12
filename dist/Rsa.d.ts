declare class Rsa {
    private usingOldRsa;
    private rsaPublicKey;
    private rsaPrivateKey;
    private oldRsaPublic;
    private oldRsaPrivate;
    constructor(publicKeyPath: string, privateKeyPath: string, usingOldRsa?: boolean);
    rsaEncrypt: (data: string) => string | undefined;
    rsaEncryptShort: (data: string) => string | undefined;
    rsaDecrypt: (data: string) => string | undefined;
    rsaDecryptShort(data: string): string | undefined;
}
export default Rsa;
