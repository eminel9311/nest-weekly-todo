import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SignInDto } from './dtos/sign-int.dto';
import * as bcrypt from 'bcrypt';
import { TokenTypeEnum } from 'src/jwt/enums/token-type.enum';
import { JwtService } from 'src/jwt/jwt.service';
import { IAuthResult } from './interfaces/auth-result.interface';
import { SignUpDto } from './dtos/sign-up.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) { }

  async signIn(signInDto: SignInDto, domain?: string | null): Promise<IAuthResult> {
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
    }
    const [accessToken, refreshToken] = await this.jwtService.generateAuthTokens(user, domain);
    return {
      // user,
      accessToken,
      refreshToken,
      // expiresIn: this.jwtService.accessTime,
    }
  }

  async signUp(signUpDto: SignUpDto, domain?: string | null): Promise<{ id: string, message: string }> {
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


  private comparePasswords(password1: string, password2: string): void {
    if (password1 !== password2) {
      throw new BadRequestException('Passwords do not match');
    }
  }
}
