import * as Joi from "joi";

export const validationSchema = Joi.object({
  // App config
  APP_ID: Joi.string().uuid({ version: 'uuidv4' }).required(),
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
  PORT: Joi.number().default(3000),
  DOMAIN: Joi.string().domain().required(),
  URL: Joi.string().uri().required(),
});