import crypto from 'crypto';
import fs from 'fs';
import Path from 'path';
import zlib from 'zlib';
import config from '../shared/config.js';

export default class Cipher {
  static hash(text, algorithm = config.hashAlgo, encoding = 'hex') {
    const hash = crypto.createHash(algorithm);
    hash.update(text);

    return hash.digest(encoding);
  }

  static random(size = config.randomSize) {
    const rnd = crypto.randomBytes(size);

    return rnd;
  }

  static randomString(encoding = 'hex') {
    const rnd = Cipher.random().toString(encoding);

    return rnd;
  }

  static sign(text) {
    const hash = Cipher.hash(text);
    const signature = `${hash.substring(0, 10)}:${hash.substring(hash.length - 10)}`;

    return signature;
  }

  static verify(text, signature) {
    const expectedSignature = Cipher.sign(text);

    return expectedSignature === signature;
  }

  static encrypt({
    value,
    encryptionKey,
    algorithm = config.encryptionALgo,
    encoding = 'hex',
  }) {
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

    return {
      publicKey,
      encrypted,
      algorithm,
      signature: Cipher.sign(value),
      encoding,
      authTag,
      provider: 'crypto',
      platform: 'autho',
    };
  }

  static decrypt({
    value,
    publicKey,
    encryptionKey,
    signature = false,
    algorithm = config.encryptionALgo,
    authTag,
    encoding = 'hex',
  }) {
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
      throw new Error('Invalid signature');
    }

    return decrypted;
  }

  static canDecrypt(options) {
    return options.platform === 'autho';
  }

  static encryptFile(inputFilePath, outputFilePath, encryptionKey) {
    const inputBuffer = fs.readFileSync(inputFilePath);
    const params = {
      value: inputBuffer,
      encryptionKey,
    };
    const encryptedData = Cipher.encrypt(params);

    fs.writeFileSync(
      outputFilePath,
      Buffer.from(JSON.stringify(encryptedData)).toString('base64')
    );
  }

  static decryptFile(inputFilePath, outputFilePath, encryptionKey) {
    const inputFileContent = fs.readFileSync(inputFilePath);
    const decoded = Buffer.from(
      inputFileContent.toString('utf-8'),
      'base64'
    ).toString('utf-8');
    const encryptedData = JSON.parse(decoded);

    if (!Cipher.canDecrypt(encryptedData)) {
      throw new Error('Invalid file');
    }

    const params = {
      ...encryptedData,
      value: encryptedData.encrypted,
      encryptionKey,
    };
    const decryptedData = Cipher.decrypt(params);
    fs.writeFileSync(outputFilePath, decryptedData);
  }

  static encryptFolder({ inputFolderPath, outputFilePath, encryptionKey, algorithm = config.encryptionALgo, encoding = 'hex' }) {
    const outputStream = fs.createWriteStream(outputFilePath);
    const gzip = zlib.createGzip();
    gzip.pipe(outputStream);
    const baseFolder = Path.basename(inputFolderPath)

    function traverseFolder(folderPath) {
      const items = fs.readdirSync(folderPath);

      for (const item of items) {
        const itemPath = Path.join(baseFolder, Path.relative(inputFolderPath, Path.join(folderPath, item)));

        if (fs.statSync(itemPath).isDirectory()) {

          traverseFolder(itemPath);
        } else {
          const fileContent = fs.readFileSync(itemPath);
          const params = {
            value: fileContent,
            encryptionKey,
            algorithm,
            encoding
          };
          const encryptedData = Cipher.encrypt(params);
          const encrypted = encryptedData.encrypted;
          delete encryptedData.encrypted;
          const encryptionMeta = Buffer.from(JSON.stringify(encryptedData)).toString('base64');
          gzip.write(`${itemPath}\n---\n${encrypted}\n---\n${encryptionMeta}\n:::\n`);
        }
      }
    }

    traverseFolder(inputFolderPath);

    gzip.end();

    return new Promise((resolve, reject) => {
      outputStream.on('finish', resolve);
      outputStream.on('error', reject);
    });
  }

  static decryptFolder({ inputFilePath, outputFolderPath, encryptionKey }) {
    const inputStream = fs.createReadStream(inputFilePath);
    const gunzip = zlib.createGunzip();
    inputStream.pipe(gunzip);

    let buff = '';

    const compileFile = (data) => {
      buff += data;
      if (buff.includes(':::')) {
        const [file, next] = buff.split('\n:::\n');
        let [filePath, encrypted, encryptionMeta] = file.split('\n---\n');
        filePath = Path.join(outputFolderPath, filePath);
        try {
          fs.mkdirSync(Path.dirname(filePath), { recursive: true });
          // eslint-disable-next-line no-unused-vars, no-empty
        } catch (error) { }
        const decoded = Buffer.from(
          encryptionMeta,
          'base64'
        ).toString('utf-8');
        const metaData = JSON.parse(decoded);
        const params = {
          ...metaData,
          value: encrypted,
          encryptionKey
        };

        const decryptedData = Cipher.decrypt(params);
        fs.writeFileSync(filePath, decryptedData);

        buff = next;
      }
    }

    gunzip.on('data', (data) => {
      compileFile(data.toString('utf8'))
    });

    return new Promise((resolve, reject) => {
      gunzip.on('end', resolve);
      gunzip.on('error', reject);
    });
  }

}
