import { IsEmail, IsOptional, IsString, IsUUID, Length } from 'class-validator';

export class UpdateUserDto {
    @IsUUID()
    id: string;

    @IsEmail()
    @IsOptional()
    email?: string;

    @IsString()
    @IsOptional()
    @Length(4, 20)
    password?: string;

    @IsString()
    @IsOptional()
    @Length(4, 20)
    repeatPassword?: string;
}
