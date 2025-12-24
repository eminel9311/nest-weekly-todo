import { Body, Controller, Post } from '@nestjs/common';
import { ApiBody, ApiCreatedResponse, ApiTags } from '@nestjs/swagger';
import { SignInDto } from './dtos/sign-int.dto';
import { AuthService } from './auth.service';
import { SignUpDto } from './dtos/sign-up.dto';

@ApiTags('Auth')
@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/sign-in')
  @ApiCreatedResponse({ description: 'User signed in successfully' })
  async signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto);
  }

  @Post('/sign-up')
  @ApiCreatedResponse({ description: 'User signed up successfully' })
  async signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }
}
