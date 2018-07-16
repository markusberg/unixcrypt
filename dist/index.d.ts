/**
 * Create sha256 or sha512 crypt of plaintext password
 * @param plaintext The plaintext password
 * @param salt optional salt, for example "$6$salt" or "$6$rounds=10000$salt"
 */
declare function encrypt(plaintext: string, salt?: string): string;
/**
 * Verify plaintext password against expected hash
 * @param plaintext The plaintext password
 * @param hash The expected hash
 */
declare function verify(plaintext: string, hash: string): boolean;
export declare const unixcrypt: {
    encrypt: typeof encrypt;
    verify: typeof verify;
};
export {};
