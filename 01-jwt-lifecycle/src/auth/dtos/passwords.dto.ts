import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length, Matches, MinLength } from 'class-validator';

export abstract class PasswordsDto {
  @ApiProperty({
    description: 'New password',
    minLength: 8,
    maxLength: 35,
    type: String,
  })
  @IsString()
  @Length(8, 35)
  public password1!: string;

  @ApiProperty({
    description: 'Password confirmation',
    minLength: 1,
    type: String,
  })
  @IsString()
  @MinLength(1)
  public password2!: string;
}