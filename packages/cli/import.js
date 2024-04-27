import fs from 'fs';
import App from './app.js';

export const importSecrets = async (backupFilePath, type = 'otp') => {
    const backupSecrets = JSON.parse(fs.readFileSync(backupFilePath).toString('utf-8'))

    const encryptionKey = await App.masterKey();
    const app = new App({ encryptionKey });
    switch (type) {
        case 'otp':
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
            break;

        default:
            throw new Error(`Unknown type: ${type}`);
    }
};
