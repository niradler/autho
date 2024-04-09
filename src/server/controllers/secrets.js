import Cipher from '../../sdk/cipher.js';

const cleanSecret = (secret) => {

    return {
        id: secret.id,
        name: secret.name,
        type: secret.type,
        createdAt: secret.createdAt,
        typeOptions: secret.typeOptions,
        protected: secret.protected,
    };
}

export const secretsRouter = (router) => {
    router.get('/secrets/:id', async (req, res) => {
        const readSecret = await req.app.secrets.get(req.params.id);
        const value = Cipher.decrypt({ ...readSecret, encryptionKey: req.app.masterPasswordHash });

        res.json({ data: { ...cleanSecret(readSecret), value } });
    });

    router.delete('/secrets/:id', (req, res) => {
        req.app.secrets.remove(req.params.id);

        res.json({ message: 'Deleted!' });
    });

    router.get('/secrets', (req, res) => {
        const data = req.app.db.get('secrets', []);

        res.json({ data: data.map(cleanSecret) });
    });

    router.post('/secrets', async (req, res) => {
        const data = req.body;
        await req.app.secrets.add(data, req.app.masterPasswordHash);

        res.json({ message: 'Created' });
    });

};

export default secretsRouter;