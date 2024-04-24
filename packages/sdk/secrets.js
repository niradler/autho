import { createSecretSchema } from '../models/Secret.js';
import Cipher from '../sdk/cipher.js';

export default class Secrets {
  constructor(db) {
    this.db = db;
  }

  get secrets() {
    return this.db.get('secrets', []);
  }

  set secrets(value) {
    this.db.set('secrets', value);
  }

  async get(id) {
    return this.secrets.find((secret) => secret.id == id);
  }

  async add(secret, encryptionKey) {
    const { value, error } = createSecretSchema.validate(secret);
    if (error) {
      throw new Error(error);
    }

    const { encrypted, ...encryption } = Cipher.encrypt({
      ...value,
      encryptionKey,
    });

    const newSecret = { ...value, ...encryption, value: encrypted }
    this.secrets = [
      ...this.secrets,
      newSecret,
    ];

    return newSecret;
  }

  async remove(id) {
    this.secrets = this.secrets.filter((secret) => secret.id != id);
  }

  async clear() {
    this.secrets = [];
  }
}
