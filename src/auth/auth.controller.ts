import { Cookie, REFRESH_TOKEN, UserAgent } from '@common/common/decarators';
import { Body, Controller, Get, Post, Res, UnauthorizedException } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';




@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) { 
     
    return this.authService.register(dto);
  }
  
  @Post('login')
  async login(@Body() dto: LoginDto, @Res() res: Response, @UserAgent() agent: string) { 
    const Tokens = await this.authService.login(dto, agent);
    this.authService.setRefreshTokenToCookies(Tokens, res)
  }
  
  @Get('refresh-tokens')
  async refreshTokin(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response, @UserAgent() agent: string) {
    if (!refreshToken) {
      throw new UnauthorizedException()
    }

    const tokens = await this.authService.refreshTokens(refreshToken, agent);

    if (!tokens) {
      throw new UnauthorizedException();
    }
    this.authService.setRefreshTokenToCookies(tokens, res)

   }
  

}
