import crypto from "crypto";

export default class Cipher {

  static hash(text, algorithm = "sha256") {
    const hash = crypto.createHash(algorithm);
    hash.update(text);

    return hash.digest("hex");
  }

  static random(size = 16) {
    const rnd = crypto.randomBytes(size);

    return rnd;
  }

  static randomString() {
    const rnd = Cipher.random().toString("hex");

    return rnd;
  }

  static sign(text) {
    const hash = Cipher.hash(text)
    const signature = `${hash.substring(0, 10)}:${hash.substring(hash.length - 10)}`;

    return signature;
  }

  static verify(text, signature) {
    const expectedSignature = Cipher.sign(text)

    return expectedSignature === signature;
  }

  static encrypt(text, encryptionKey, algorithm = "aes-256-ctr") {
    const publicKey = Cipher.randomString();
    let cipher = crypto.createCipheriv(
      algorithm,
      Buffer.from(encryptionKey, "hex"),
      Buffer.from(publicKey, "hex"),
    );
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    encrypted = encrypted.toString("hex");

    return { publicKey, encrypted, algorithm, signature: Cipher.sign(text) };
  }

  static decrypt(encryptedText, publicKey, encryptionKey, signature, algorithm = "aes-256-ctr") {
    encryptedText = Buffer.from(encryptedText, "hex");

    let decipher = crypto.createDecipheriv(
      algorithm,
      Buffer.from(encryptionKey, "hex"),
      Buffer.from(publicKey, "hex")
    );

    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    decrypted = decrypted.toString();

    if (!Cipher.verify(decrypted, signature)) {
      throw new Error("Invalid signature")
    }

    return decrypted;
  }
}
