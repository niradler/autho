import Joi from 'joi';
import Cipher from "../sdk/cipher.js";

export const createSecretSchema = Joi.object({
    id: Joi.string().default(Cipher.random()), 
    protected: Joi.boolean().default(false), // ask for password
    name: Joi.string().required(),
    type: Joi.string().required().valid('otp'),
    value: Joi.string().required(),
    typeOptions: Joi.object().default({}),
    createdAt: Joi.date().default(new Date()),
})