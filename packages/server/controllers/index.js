import secretsRouter from './secrets.js';
import authRouter from './auth.js';

export const controllers = (router) => {
  secretsRouter(router);
  authRouter(router);

  return router;
};

export default controllers;
