import Joi from 'joi';
import { randomUUID } from 'node:crypto';

export const createSecretSchema = Joi.object({
  id: Joi.string().default(randomUUID()),
  protected: Joi.boolean().default(false),
  name: Joi.string().required(),
  type: Joi.string().required().valid('otp', 'password', 'note'),
  value: Joi.string().required(),
  typeOptions: Joi.object().default({}),
  createdAt: Joi.date().default(new Date()),
});
