import { IUser } from "../../users/interfaces/user.interface";

export interface IAuthSignInResult {
  // user: IUser;
  accessToken: string;
  refreshToken: string;
  // expiresIn: number;
}

export interface IAuthSignUpResult {
  id: string;
  message: string;
}

export interface IAuthLogoutResult {
  message: string;
}