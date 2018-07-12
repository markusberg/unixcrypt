declare function crypt(plaintext: string, salt?: string): string;
declare function verifyPassword(plaintext: string, hash: string): boolean;
export declare const sha512crypt: {
    crypt: typeof crypt;
    verifyPassword: typeof verifyPassword;
};
export {};
