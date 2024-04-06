import crypto from "crypto";
import fs from "fs";

const RANDOM_SIZE = process.env.AUTHO_RANDOM_SIZE || 16;
const ENCRYPTION_ALGO = process.env.AUTHO_ENCRYPTION_ALGO || "aes-256-gcm";
const HASH_ALGO = process.env.AUTHO_HASH_ALGO || "sha256";

export default class Cipher {

  static hash(text, algorithm = HASH_ALGO, encoding = "hex") {
    const hash = crypto.createHash(algorithm);
    hash.update(text);

    return hash.digest(encoding);
  }

  static random(size = RANDOM_SIZE) {
    const rnd = crypto.randomBytes(size);

    return rnd;
  }

  static randomString(encoding = "hex") {
    const rnd = Cipher.random().toString(encoding);

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

  static encrypt({ value, encryptionKey, algorithm = ENCRYPTION_ALGO, encoding = "hex" }) {
    const publicKey = Cipher.randomString();
    let cipher = crypto.createCipheriv(
      algorithm,
      Buffer.from(encryptionKey, encoding),
      Buffer.from(publicKey, encoding),
      { authTagLength: 16 }
    );
    let encrypted = cipher.update(value);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    encrypted = encrypted.toString(encoding);
    const authTag = cipher.getAuthTag().toString(encoding);

    return { publicKey, encrypted, algorithm, signature: Cipher.sign(value), encoding, authTag };
  }

  static decrypt({ value, publicKey, encryptionKey, signature = false, algorithm = ENCRYPTION_ALGO, authTag, encoding = "hex" }) {
    value = Buffer.from(value, encoding);

    let decipher = crypto.createDecipheriv(
      algorithm,
      Buffer.from(encryptionKey, encoding),
      Buffer.from(publicKey, encoding),
      { authTagLength: 16 }
    );
    if (authTag) {
      decipher.setAuthTag(Buffer.from(authTag, encoding));
    }
    let decrypted = decipher.update(value);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    decrypted = decrypted.toString();

    if (signature && !Cipher.verify(decrypted, signature)) {
      throw new Error("Invalid signature")
    }

    return decrypted;
  }

  static encryptFile(inputFilePath, outputFilePath, encryptionKey) {
    const inputBuffer = fs.readFileSync(inputFilePath);
    const encryptedData = Cipher.encrypt(inputBuffer, encryptionKey);

    fs.writeFileSync(outputFilePath, Buffer.from(JSON.stringify(encryptedData)));
  }

  static decryptFile(inputFilePath, outputFilePath, encryptionKey) {
    const inputFileContent = fs.readFileSync(inputFilePath);
    const encryptedData = JSON.parse(inputFileContent.toString());

    const decryptedData = Cipher.decrypt(encryptedData, encryptionKey);
    fs.writeFileSync(outputFilePath, decryptedData);
  }

}
