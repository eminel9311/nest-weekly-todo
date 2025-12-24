import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '../jwt/jwt.module';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from 'src/jwt/jwt.service';
@Module({
  imports: [JwtModule],
  providers: [AuthService, JwtService, PrismaService],
  controllers: [AuthController]
})
export class AuthModule {}
