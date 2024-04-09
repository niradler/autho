export const authRouter = (router) => {
    router.get('/auth/hash', async (req, res) => {

        res.json({ data: { hash: req.app.masterPasswordHash } });
    });
};

export default authRouter;