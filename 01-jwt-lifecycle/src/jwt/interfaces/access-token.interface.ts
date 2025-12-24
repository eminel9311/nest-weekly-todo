import { ITokenBase } from "./token-base.interface";

export interface IAccessPayload {
  userId: string;
}

export interface IAccessToken extends IAccessPayload, ITokenBase {}
