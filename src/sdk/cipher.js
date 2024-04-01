import crypto from "crypto";

export default class Cipher {
  constructor(config) {
    this.config = config;
    this.salt = config.get("salt", "");
  }

  static hash(text) {
    const hash = crypto.createHash("sha256");
    hash.update(text);

    return hash.digest("hex");
  }

  static random() {
    const rnd = crypto.randomBytes(16).toString("hex");

    return rnd;
  }

  static createKey(salt="") {
    const rnd = Cipher.random(salt)

    return Cipher.hash(salt+rnd);
  }

  encrypt(text, password) {
    const publicKey = Cipher.createKey(this.salt);
    const cipher = crypto.createCipher(
      "aes-256-cbc",
       publicKey + password
    );
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");

    return { publicKey, encrypted };
  }

  decrypt(encryptedText, publicKey, password) {
    const decipher = crypto.createDecipher(
      "aes-256-cbc",
      publicKey + password
    );
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }
}
