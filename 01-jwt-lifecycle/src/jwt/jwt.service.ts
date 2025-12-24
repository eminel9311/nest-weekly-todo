import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IUser } from '../users/interfaces/user.interface';
import { TokenTypeEnum } from './enums/token-type.enum';
import * as jwt from 'jsonwebtoken';
import { IJwt } from '../config/interfaces/jwt.interface';
import { IRefreshPayload } from './interfaces/refresh-token.interface';
import { IAccessPayload } from './interfaces/access-token.interface';
import { v4 } from 'uuid';

@Injectable()
export class JwtService {
  private readonly jwtConfig: IJwt;
  private readonly issuer: string;
  private readonly domain: string;
  constructor(private readonly configService: ConfigService) {
    this.jwtConfig = this.configService.get<IJwt>('jwt');
    this.issuer = this.configService.get<string>('id');
    this.domain = this.configService.get<string>('domain');
  }


  public get accessTime(): number {
    return this.jwtConfig.access.time;
  }


  public async generateToken(
    user: IUser,
    tokenType: TokenTypeEnum,
    domain?: string | null,
    tokenId?: string
  ): Promise<string> {
    const jwtOptions: jwt.SignOptions = {
      issuer: this.issuer,
      subject: user.email,
      audience: domain ?? this.domain,
      algorithm: 'HS256',
    }
    switch (tokenType) {
      case TokenTypeEnum.ACCESS:
        const { privateKey, time: accessTime } = this.jwtConfig.access;
        const accessToken = await JwtService.generateTokenAsync(
          { userId: user.id },
          privateKey,
          {
            ...jwtOptions,
            expiresIn: accessTime,
            algorithm: 'RS256',
          }
        )
        return accessToken;
      case TokenTypeEnum.REFRESH:
        const { secret: refreshSecret, time: refreshTime } = this.jwtConfig.refresh;
        const refreshToken = await JwtService.generateTokenAsync(
          { userId: user.id, version: 1, tokenId: tokenId ?? v4() },
          refreshSecret,
          {
            ...jwtOptions,
            expiresIn: refreshTime,
            algorithm: 'HS256',
          }
        )
        return refreshToken;
    }
  }

  public async generateAuthTokens(
    user: IUser,
    domain?: string | null,
    tokenId?: string,
  ): Promise<[string, string]> {
    return Promise.all([
      this.generateToken(user, TokenTypeEnum.ACCESS, domain, tokenId),
      this.generateToken(user, TokenTypeEnum.REFRESH, domain, tokenId),
    ])
  }

  private static async generateTokenAsync(
    payload: IAccessPayload | IRefreshPayload,
    secret: string,
    options: jwt.SignOptions
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      jwt.sign(payload, secret, options, (err, token) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(token);
      })
    })
  }
}

