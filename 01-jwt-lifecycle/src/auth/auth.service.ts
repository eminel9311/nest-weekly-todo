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
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or username or password');
    };

    // Xóa tất cả refresh token cũ của user (single active token strategy)
    await this.revokeAllRefreshTokens(user.id);


    const [accessToken, refreshToken] = await this.jwtService.generateAuthTokens(user, domain);
    await this.saveRefreshToken(refreshToken, user.id);
    return {
      // user,
      accessToken,
      refreshToken,
      // expiresIn: this.jwtService.accessTime,
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

  public async logout(logoutDto: LogoutDto): Promise<IAuthLogoutResult> {
    // Xóa tất cả refresh token cũ của user (single active token strategy)
    await this.revokeAllRefreshTokens(logoutDto.userId);
    return {
      message: 'User logged out successfully',
    };
  }


  private comparePasswords(password1: string, password2: string): void {
    if (password1 !== password2) {
      throw new BadRequestException('Passwords do not match');
    }
  }

  // save refresh token(hashed) to database
  private async saveRefreshToken(refreshToken: string, userId: string): Promise<string> {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    const data = await this.prisma.refreshToken.create({
      data: {
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
