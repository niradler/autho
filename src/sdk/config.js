import Conf from "conf";

const { AUTHO_ENCRYPTION_KEY = "", AUTHO_NAME = 'default' } = process.env;

export default class Config {
    constructor({
        encryptionKey = AUTHO_ENCRYPTION_KEY,
        configName = AUTHO_NAME
    }) {
        this.config = new Conf({ projectName: "autho", encryptionKey, configName });
    }

    get(key, defaultValue) {
        return this.config.get(key, defaultValue);
    }

    set(key, value) {
        this.config.set(key, value);
    }

}

