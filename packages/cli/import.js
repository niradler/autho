import fs from 'fs';
import App from './app.js';

const main = async (backupFilePath) => {
    const backupSecrets = fs.readFileSync(backupFilePath).toString('utf-8').split('\n');

    const encryptionKey = await App.masterKey();
    const app = new App({ encryptionKey });

    for (let secret of backupSecrets) {
        if (!secret) continue;

        const newSecret = {
            name: secret.name,
            type: "otp",
            protected: false,
            value: secret.secret,
            typeOptions: {
                username: secret.username,
                digits: secret.digits
            },
        };
        await app.secrets.add(newSecret, encryptionKey);
    }
};
main();