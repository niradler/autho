import Secrets from '../sdk/secrets.js';
import DB from '../sdk/db.js';
import Cipher from '../sdk/cipher.js';
import config from '../shared/config.js';
import { ask } from './utils.js';

export default class App {
  constructor(options = {}) {
    this.encryptionKey = options.encryptionKey || config.masterPasswordHash;
    this.dataFolder = options.dataFolder || config.dataFolder;
    this.name = options.name || 'default';

    this.db = new DB({
      encryptionKey: this.encryptionKey,
      dataFolder: this.dataFolder,
      name: this.name,
    });
    this.secrets = new Secrets(this.db);
  }

  static async masterKey(masterPassword, masterPasswordHash) {
    masterPassword = masterPassword || config.masterPassword;

    if (masterPasswordHash) {
      return masterPasswordHash;
    } else if (!masterPassword) {
      masterPassword = await ask({
        name: 'masterPassword',
        message: 'Password:',
        type: 'password',
        required: true,
      });
    }

    masterPasswordHash = Cipher.hash(masterPassword);

    return masterPasswordHash;
  }
}
