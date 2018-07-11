
function crypt(plaintext: string, salt?: string, rounds?: number) {
  return "apa";
}

function verifyPassword(plaintext: string, hash: string): boolean {
  return true;
}

export const sha512crypt = {
  crypt,
  verifyPassword,
}
