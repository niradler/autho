import crypto from "crypto";

const algorithm = "aes-256-ctr";
const IV_LENGTH = 16;

export default class Cipher {
  constructor() { }

  static hash(text) {
    const hash = crypto.createHash("sha256");
    hash.update(text);

    return hash.digest("hex");
  }

  static random(size = IV_LENGTH) {
    const rnd = crypto.randomBytes(size);

    return rnd;
  }

  static randomString() {
    const rnd = Cipher.random().toString("hex");

    return rnd;
  }

  static encrypt(text, password) {
    const publicKey = Cipher.randomString();
    let cipher = crypto.createCipheriv(
      algorithm,
      Buffer.from(password, "hex"),
      Buffer.from(publicKey, "hex"),
    );
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    encrypted = encrypted.toString("hex");

    return { publicKey, encrypted };
  }

  static decrypt(encryptedText, publicKey, password) {
    encryptedText = Buffer.from(encryptedText, "hex");
    let decipher = crypto.createDecipheriv(
      algorithm,
      Buffer.from(password, "hex"),
      Buffer.from(publicKey, "hex")
    );
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString();
  }
}
