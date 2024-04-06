import Secrets from "./sdk/secrets.js";
import DB from "./sdk/db.js";
import Cipher from "./sdk/cipher.js";

//type AppOptions = {
//   masterPasswordHash?: string;
//   masterPassword?: string;
//   appFolder?: string;
// };

export default class App {
    constructor(options = {}) {
        let masterPasswordHash =
            options.masterPasswordHash || process.env.AUTHO_MASTER_PASSWORD_HASH;
        const masterPassword = options.masterPassword || process.env.AUTHO_MASTER_PASSWORD;
        if (!masterPasswordHash && !masterPassword) {
            throw new Error("Master password or master password hash is required")
        }
        masterPasswordHash =
            masterPasswordHash ||
            Cipher.hash(masterPassword);

        this.db = new DB({ encryptionKey: masterPasswordHash, dataFolder: options.dataFolder});
        this.secrets = new Secrets(this);
    }

}