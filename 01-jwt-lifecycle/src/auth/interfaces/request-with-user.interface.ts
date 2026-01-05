import { IAccessToken } from "../../jwt/interfaces/access-token.interface";

export interface RequestWithUser extends Request {
  user: IAccessToken;
}