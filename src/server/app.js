import express from 'express';

const { PORT = 8080 } = process.env;

export class App {
  constructor() {
    this.app = express();
    this.router = express.Router();
    this.middlewares = [];
  }

  routes(fn) {
    fn(this.router);

    return this.router;
  }

  uses(middlewares) {
    this.middlewares = middlewares;
  }

  init() {
    for (const middleware of this.middlewares) {
      this.app.use(middleware);
    }
    this.app.use(this.router);
  }

  start(port = PORT) {
    this.init();
    this.app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  }
}

export default App;