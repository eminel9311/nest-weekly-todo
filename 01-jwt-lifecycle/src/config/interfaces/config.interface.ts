import { IDbConfig } from "./db.config.interface";
import { IJwt } from "./jwt.interface";

export interface IConfig {
  readonly id: string;
  readonly url: string;
  readonly port: number;
  readonly domain: string;
  readonly db: IDbConfig;
  readonly jwt: IJwt;
}
  