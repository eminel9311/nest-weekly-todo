import { IConfig } from "./interfaces/config.interface";
import { LogLevel } from "@nestjs/common";
import { LogDefinition } from "src/generated/prisma/internal/prismaNamespace";

export function config(): IConfig {
  return {
    id: process.env.APP_ID,
    url: process.env.URL,
    port: parseInt(process.env.PORT, 10),
    domain: process.env.DOMAIN,
    db: {
      connectionString: process.env.DATABASE_URL,
      log: ['query', 'info', 'warn', 'error'] as (LogLevel | LogDefinition)[],
      errorFormat: 'pretty',
      transactionOptions: {
        maxWait: 2000,
        timeout: 5000,
      }
    },
    jwt: {
      access: {
        publicKey: process.env.JWT_ACCESS_PUBLIC_KEY,
        privateKey: process.env.JWT_ACCESS_PRIVATE_KEY,
        time: parseInt(process.env.JWT_ACCESS_TIME, 10),
      },
      refresh: {
        secret: process.env.JWT_REFRESH_SECRET,
        time: parseInt(process.env.JWT_REFRESH_TIME, 10),
      }
    }
  };
}