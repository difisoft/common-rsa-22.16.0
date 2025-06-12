declare class Rsa {
    private rsaPublicKey;
    private rsaPrivateKey;
    constructor(publicKeyPath: string, privateKeyPath: string);
    rsaEncrypt: (data: string) => string;
    rsaEncryptShort: (data: string) => string;
    rsaDecrypt: (data: string) => string;
    rsaDecryptShort(data: string): string;
}
export default Rsa;
