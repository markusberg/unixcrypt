"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const roundsDefault = 5000;
const roundsMin = 1000;
const roundsMax = 999999999;
const dictionary = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/**
 * Convenience function for generating a random string
 * @param length Length of salt
 */
function getSalt(length) {
    var result = "";
    for (let i = 0; i < length; i++) {
        result += dictionary[Math.floor(Math.random() * dictionary.length)];
    }
    return result;
}
/**
 * Parse salt into pieces
 * @param salt Standard salt, "$6$rounds=1234&saltsalt" or "$6$saltsalt"
 */
function parseSalt(salt) {
    let id = "6";
    let saltString = getSalt(16);
    let rounds = roundsDefault;
    if (salt) {
        const parts = salt.split('$');
        id = parts[1];
        if (parts.length === 4) {
            const test = parts[2].match(/^rounds=(\d*)$/);
            rounds = test ? Number(test[1]) : roundsDefault;
            saltString = parts[3];
        }
        else {
            rounds = roundsDefault;
            saltString = parts[2];
        }
    }
    // sanity-check rounds
    rounds =
        rounds < roundsMin
            ? roundsMin
            : rounds > roundsMax
                ? rounds = roundsMax
                : rounds;
    // sanity-check saltString
    saltString = saltString.substr(0, 16);
    return {
        id,
        saltString,
        rounds,
    };
}
function crypt(plaintext, salt) {
    let conf = parseSalt(salt);
    console.debug(conf);
    return "apa";
}
function verifyPassword(plaintext, hash) {
    return true;
}
exports.sha512crypt = {
    crypt,
    verifyPassword,
};
//# sourceMappingURL=index.js.map