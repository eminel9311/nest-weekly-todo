import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IUser } from '../users/interfaces/user.interface';
import { TokenTypeEnum } from './enums/token-type.enum';
import * as jwt from 'jsonwebtoken';
import { IJwt } from '../config/interfaces/jwt.interface';
import { IRefreshPayload } from './interfaces/refresh-token.interface';
import { IAccessPayload } from './interfaces/access-token.interface';
import { v4 } from 'uuid';
import { ITokenBase } from './interfaces/token-base.interface';

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

  public async generateAuthTokens(
    user: IUser,
    domain?: string | null,
    tokenId?: string,
  ): Promise<[string, string]> {
    return Promise.all([
      this.generateToken(user, TokenTypeEnum.ACCESS, domain),
      this.generateToken(user, TokenTypeEnum.REFRESH, domain, tokenId),
    ])
  }

  public async generateToken(
    user: IUser,
    tokenType: TokenTypeEnum,
    domain?: string | null,
    tokenId?: string,
  ): Promise<string> {
    const baseOptions = this.createBaseJwtOptions(user, domain);
    switch (tokenType) {
      case TokenTypeEnum.ACCESS:
        return this.generateAccessToken(user, baseOptions);
      case TokenTypeEnum.REFRESH:
        return this.generateRefreshToken(user, baseOptions, tokenId ?? v4());
      default:
        throw new BadRequestException('Invalid token type');
    }
  }


  public async verifyAccessToken(accessToken: string): Promise<IAccessPayload & ITokenBase> {
    const { publicKey } = this.jwtConfig.access;
    return JwtService.verifyToken(accessToken, publicKey, 'RS256');
  }



  public async verifyRefreshToken(refreshToken: string): Promise<IRefreshPayload & ITokenBase> {
    const { secret } = this.jwtConfig.refresh;
    return JwtService.verifyToken(refreshToken, secret, 'HS256');
  }


  private createBaseJwtOptions(user: IUser, domain?: string | null): jwt.SignOptions {
    return {
      issuer: this.issuer,
      subject: user.email,
      audience: domain ?? this.domain,
    }
  }

  private async generateAccessToken(
    user: IUser,
    baseOptions: jwt.SignOptions
  ): Promise<string> {
    const { privateKey, time } = this.jwtConfig.access;

    return JwtService.signToken(
      { userId: user.id },
      privateKey,
      {
        ...baseOptions,
        expiresIn: time,
        algorithm: 'RS256',
      }
    );
  }


  private async generateRefreshToken(
    user: IUser,
    baseOptions: jwt.SignOptions,
    tokenId: string,
  ): Promise<string> {
    const { secret, time } = this.jwtConfig.refresh;

    return JwtService.signToken(
      { userId: user.id, version: 1, tokenId: tokenId },
      secret,
      {
        ...baseOptions,
        expiresIn: time,
        algorithm: 'HS256',
      }
    )
  }

  // Helper: Sign token
  private static async signToken(
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

  // Helper: Verify token
  private static async verifyToken<T>(
    token: string,
    secretOrPublicKey: string,
    algorithm: string
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        secretOrPublicKey,
        { algorithm: [algorithm] },
        (err, decoded) => {
          if (err) {
            // Phân loại lỗi cụ thể
            if (err.name === 'TokenExpiredError') {
              reject(new Error('Token expired'));
            } else if (err.name === 'JsonWebTokenError') {
              reject(new Error('Invalid token'));
            } else {
              reject(err);
            }
          } else {
            resolve(decoded);
          }
        }
      )
    })
  }
}

