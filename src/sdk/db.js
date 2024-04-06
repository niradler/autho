import Conf from "conf";

const projectName = "autho";
// configFileMode 0o600 

export default class DB {
    constructor({
        encryptionKey,
        configName = 'default',
        dataFolder
    }) {
        this.encryptionKey = encryptionKey;
        this.client = new Conf({ projectName, encryptionKey, configName: `${projectName}_${configName}`, cwd: dataFolder, projectSuffix: '' });
    }

    get(key, defaultValue) {
        return this.client.get(key, defaultValue);
    }

    set(key, value) {
        this.client.set(key, value);
    }

    clear() {
        this.client.clear()
    }

    store() {
        return this.client.store
    }

    path() {
        return this.client.path
    }

}

