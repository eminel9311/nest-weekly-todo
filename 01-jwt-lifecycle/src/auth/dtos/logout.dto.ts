import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsUUID } from "class-validator";


export abstract class LogoutDto {
  @ApiProperty({
    description: 'The user ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
    type: String,
  })
  @IsString()
  @IsUUID()
  public userId: string;
}