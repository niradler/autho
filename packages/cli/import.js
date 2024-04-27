import fs from 'fs';

const createSecret = async (secret, app) => {
    let created = false;
    switch (secret.type) {
        case 'otp': {
            const newSecret = {
                name: secret.name,
                type: secret.type,
                protected: false,
                value: secret.secret,
                typeOptions: {
                    username: secret.username,
                    digits: secret.digits,
                    description: secret.description
                },
            };
            created = await app.secrets.add(newSecret, app.encryptionKey);
        }
            break;

        case 'password': {
            const newSecret = {
                name: secret.name,
                type: secret.type,
                protected: false,
                value: secret.secret,
                typeOptions: {
                    username: secret.username,
                    url: secret.url,
                    description: secret.description
                },
            };
            created = await app.secrets.add(newSecret, app.encryptionKey);
        }
            break;

        case 'note': {
            const newSecret = {
                name: secret.name,
                type: secret.type,
                protected: false,
                value: secret.secret,
                typeOptions: {
                    description: secret.description
                },
            };
            created = await app.secrets.add(newSecret, app.encryptionKey);
        }
            break;

        default:
            throw new Error(`Unknown type: ${secret.type}`);
    }

    if (created)
        console.log(`Secret created: ${created.id}`)
}

export const importSecrets = async (app, backupFilePath) => {
    const backupSecrets = JSON.parse(fs.readFileSync(backupFilePath).toString('utf-8'))

    for (let secret of backupSecrets) {
        if (!secret) continue;
        await createSecret(secret, app);
    }
};
