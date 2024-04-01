import Conf from "conf";

export default class Config {
    constructor({
        encryptionKey,
        configName='default'
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

