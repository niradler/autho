import chalk from 'chalk';
import config from './config.js';

const levelToColor = {
  info: 'green',
  debug: 'blue',
  error: 'red',
};

const levelToNumber = {
  debug: 1,
  info: 3,
  error: 4,
};

export class Logger {
  constructor(options = {}) {
    this.logLevel = options.logLevel || config.logLevel || 'info';
  }

  output(level, args) {
    if (['info', 'debug', 'error'].indexOf(level) < 0) {
      throw new Error('Invalid log level');
    }

    if (levelToNumber[this.logLevel] > levelToNumber[level]) {
      return;
    }

    console[level](
      `[${new Date().toLocaleString()}]`,
      chalk[levelToColor[level]](level.toUpperCase()),
      ...args
    );
  }

  info(...args) {
    this.output('info', args);
  }

  debug(...args) {
    this.output('debug', args);
  }

  error(...args) {
    this.output('error', args);
  }
}
