import { Cookie, CurrentUser, Public, REFRESH_TOKEN, Roles, UserAgent } from '@common/common/decarators';
import {
    Body,
    ClassSerializerInterceptor,
    Controller,
    Get,
    HttpStatus,
    Post,
    Req,
    Res,
    UnauthorizedException,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { UserResponse } from '@user/resonse';
import { GoogleGuard } from './guards/google.guard';

@Public()
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}
    @UseInterceptors(ClassSerializerInterceptor)
    @Post('register')
    async register(@Body() dto: RegisterDto) {
        const user = await this.authService.register(dto);
        return new UserResponse(user);
    }

    @Post('login')
    async login(@Body() dto: LoginDto, @Res() res: Response, @UserAgent() agent: string) {
        const Tokens = await this.authService.login(dto, agent);
        this.authService.setRefreshTokenToCookies(Tokens, res);
    }

    @Get('refresh-tokens')
    async refreshTokin(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response, @UserAgent() agent: string) {
        if (!refreshToken) {
            throw new UnauthorizedException();
        }

        const tokens = await this.authService.refreshTokens(refreshToken, agent);

        if (!tokens) {
            throw new UnauthorizedException();
        }
        this.authService.setRefreshTokenToCookies(tokens, res);
    }

    @Get('logout')
    async logout(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response) {
        console.log(refreshToken);
        if (!refreshToken) {
            res.sendStatus(HttpStatus.OK);
        } else {
            await this.authService.deleteRefreshToken(refreshToken);
            res.cookie(REFRESH_TOKEN, '', { httpOnly: true, secure: true, expires: new Date() });
            res.sendStatus(HttpStatus.OK);
        }
    }

    @UseGuards(GoogleGuard)
    @Get('google')
    googleAuth() {}

    @UseGuards(GoogleGuard)
    @Get('google/callback')
    googleAuthCallback(@Req() req: Request) {
        return req.user;
    }
}
