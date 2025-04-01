import { IsPasswordMatchingConstraint } from "@common/common/decarators";
import { IsEmail, IsString, MinLength, Validate } from "class-validator";

export class RegisterDto {
    @IsEmail()
    email: string;

    @MinLength(6)
    @IsString()
    password: string;

    @MinLength(6)
    @IsString()
    @Validate(IsPasswordMatchingConstraint)
    passwordRepeat: string;
}