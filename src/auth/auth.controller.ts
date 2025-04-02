import { Body, Controller, Get, Post, Res } from '@nestjs/common';
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
  async login(@Body() dto: LoginDto, @Res() res: Response) { 
    const Tokens = await this.authService.login(dto);
    this.authService.setRefreshTokenToCookies(Tokens, res)
  }
  
  @Get('refresh')
  refreshTokin() { }
  

}
