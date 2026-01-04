import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsUUID } from "class-validator";


export abstract class LogoutDto {
  @ApiProperty({
    description: 'The access token to identify the user',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
    type: String,
  })
  @IsString()
  public accessToken: string;
}