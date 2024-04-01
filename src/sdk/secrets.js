import { createSecretSchema } from "../models/Secret.js";
import Cipher from "./cipher.js";

export default class Secrets {
  constructor(config) {
    this.config = config;
    this.cipher = new Cipher(config);
  }

  get secrets() {
    return this.config.get("secrets", []);
  }

  set secrets(value) {
    this.config.set("secrets", value);
  }

  async get(id) {
    return this.secrets.find((secret) => secret.id == id);
  }

  async add(secret, password) {
    const { value, error } = createSecretSchema.validate(secret);
    if (error) {
      throw new Error(error);
    }

    const { publicKey, encrypted } = this.cipher.encrypt(value.value, password);
    value.value = encrypted;
    value.publicKey = publicKey;

    this.secrets = [...this.secrets, value];
  }

  async remove(id) {
    this.secrets = this.secrets.filter((secret) => secret.id != id);
  }
}
