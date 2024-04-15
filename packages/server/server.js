import App from './app.js';
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import morgan from 'morgan';
import { authMiddleware } from './middlewares/auth.js';
import controllers from './controllers/index.js';
import { fileURLToPath } from 'url';
import path from 'path';

const app = new App();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.app.set('views', path.join(__dirname, 'views'));
app.app.set('view engine', 'ejs');

const viewsContext = (req, res, next) => {
  res.locals = {
    title: 'Autho',
    apiUrl: 'http://localhost:8051/api',
  };
  next();
};

app.uses([
  express.json(),
  bodyParser.urlencoded({ extended: true }),
  cors(),
  morgan('dev'),
  viewsContext,
]);

app.routes((router) => {
  router.use('/public', express.static(path.join(__dirname, 'public')));
  const apiRouter = express.Router();
  const apiRoutes = controllers(apiRouter);
  router.use('/api', authMiddleware, apiRoutes);

  router.get('/', (req, res) => {
    res.render('index', {});
  });
});

app.start();
