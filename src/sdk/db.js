import Conf from "conf";

const { AUTHO_ENCRYPTION_KEY = "", AUTHO_NAME = 'default' } = process.env;

export default class DB {
    constructor({
        encryptionKey = AUTHO_ENCRYPTION_KEY,
        configName = AUTHO_NAME
    }) {
        this.encryptionKey = encryptionKey;
        this.client = new Conf({ projectName: "autho", encryptionKey, configName });
    }

    get(key, defaultValue) {
        return this.client.get(key, defaultValue);
    }

    set(key, value) {
        this.client.set(key, value);
    }

}

