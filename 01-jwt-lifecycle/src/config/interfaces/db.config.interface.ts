import { LogLevel } from "@nestjs/common";
import { ErrorFormat, LogDefinition } from "src/generated/prisma/internal/prismaNamespace";


export interface IDbConfig {
  readonly connectionString: string;
  readonly log: (LogLevel | LogDefinition)[];
  readonly errorFormat: ErrorFormat;
  readonly transactionOptions: {
    readonly maxWait: number;
    readonly timeout: number;
  };
}