import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SignInDto } from './dtos/sign-in.dto';
import * as bcrypt from 'bcrypt';
import { TokenTypeEnum } from 'src/jwt/enums/token-type.enum';
import { JwtService } from 'src/jwt/jwt.service';
import { IAuthLogoutResult, IAuthSignInResult, IAuthSignUpResult } from './interfaces/auth-result.interface';
import { SignUpDto } from './dtos/sign-up.dto';
import { IJwt } from '../config/interfaces/jwt.interface';
import { ConfigService } from '@nestjs/config';
import { LogoutDto } from './dtos/logout.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { IRefreshPayload } from '../jwt/interfaces/refresh-token.interface';
import { ITokenBase } from '../jwt/interfaces/token-base.interface';
import { v4 } from 'uuid';
import { IAccessPayload, IAccessToken } from '../jwt/interfaces/access-token.interface';

@Injectable()
export class AuthService {
  private jwtConfig: IJwt;
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.jwtConfig = this.configService.get<IJwt>('jwt');
  }

  public async signIn(signInDto: SignInDto, domain?: string | null): Promise<IAuthSignInResult> {
    const { emailOrUsername, password } = signInDto;

    // Step 1: Find user
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [
          { email: emailOrUsername },
          { username: emailOrUsername },
        ],
      },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid email or username or password');
    }
    // Step 2: Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or username or password');
    };

    // Step 3: Revoke all existing refresh tokens (Single Active Token Strategy)
    await this.revokeAllRefreshTokens(user.id);


    // Step 4: Generate new tokens
    const tokenId = v4();
    const [accessToken, refreshToken] = await this.jwtService.generateAuthTokens(user, domain, tokenId);

    // Step 5: Save refresh token (hashed) to database
    await this.saveRefreshToken(refreshToken, user.id, tokenId);

    // Step 6: Return tokens
    return {
      accessToken,
      refreshToken,
    }
  }

  public async signUp(signUpDto: SignUpDto, domain?: string | null): Promise<IAuthSignUpResult> {
    const { name, email, password1, password2 } = signUpDto;
    this.comparePasswords(password1, password2);
    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        username: email,
        password: await bcrypt.hash(password1, 10),
      }
    });
    return {
      id: user.id,
      message: 'User created successfully',
    };
  }


  public async logout(userId: string): Promise<IAuthLogoutResult> {
    await this.revokeAllRefreshTokens(userId);
    return {
      message: 'User logged out successfully',
    };
  }


  public async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<IAuthSignInResult> {
    const { refreshToken } = refreshTokenDto;

    // Step 1: Verify JWT signature và decode payload
    let payload: IRefreshPayload & ITokenBase;
    try {
      payload = await this.jwtService.verifyRefreshToken(refreshToken);
    } catch (error) {
      if (error.message === 'Token expired') {
        throw new UnauthorizedException('Refresh token expired');
      }
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Step 2: Find user
    const user = await this.prisma.user.findUnique({
      where: {
        id: payload.userId,
      }
    })

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Step 3-6: Tất cả trong 1 transaction tránh lỗi race condition
    const result = await this.prisma.$transaction(async (tx) => {
      // Find token in database
      const storedToken = await tx.refreshToken.findFirst({
        where: { userId: user.id, tokenId: payload.tokenId },
      });

      if (!storedToken) {
        throw new UnauthorizedException('Refresh token not found or revoked');
      }

      // Verify token
      const isMatch = await bcrypt.compare(refreshToken, storedToken.token);
      if (!isMatch) {
        throw new UnauthorizedException('Refresh token not found or revoked');
      }

      // Check expiration
      if (storedToken.expiresAt < new Date()) {
        await tx.refreshToken.delete({ where: { id: storedToken.id } });
        throw new UnauthorizedException('Refresh token expired');
      }

      // Token Rotation: Delete old token
      await tx.refreshToken.delete({ where: { id: storedToken.id } });

      // Generate new tokens
      const newTokenId = v4();
      const [newAccessToken, newRefreshToken] = await this.jwtService.generateAuthTokens(user, undefined, newTokenId);

      // Save new refresh token (hashed) to database
      const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);
      await tx.refreshToken.create({
        data: {
          tokenId: newTokenId,
          token: hashedNewRefreshToken,
          expiresAt: new Date(Date.now() + this.jwtConfig.refresh.time * 1000),
          userId: user.id,
        }
      })

      return {
        newAccessToken,
        newRefreshToken,
      }
    })

    return {
      accessToken: result.newAccessToken,
      refreshToken: result.newRefreshToken,
    }

  }

  private comparePasswords(password1: string, password2: string): void {
    if (password1 !== password2) {
      throw new BadRequestException('Passwords do not match');
    }
  }

  // save refresh token(hashed) to database
  private async saveRefreshToken(refreshToken: string, userId: string, tokenId: string): Promise<string> {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    const data = await this.prisma.refreshToken.create({
      data: {
        tokenId,
        token: hashedRefreshToken,
        expiresAt: new Date(Date.now() + this.jwtConfig.refresh.time * 1000),
        userId,
      }
    })
    return data.id;
  }

  private async revokeAllRefreshTokens(userId: string): Promise<void> {
    await this.prisma.refreshToken.deleteMany({
      where: { userId },
    });
  }
}
