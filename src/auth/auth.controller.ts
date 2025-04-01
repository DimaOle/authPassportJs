import { Body, Controller, Get, Post } from '@nestjs/common';
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
  async login(@Body() dto: LoginDto) { 
    const token = await this.authService.login(dto)
    return {accessToken: token.accessToken}
     
  }
  
  @Get('refresh')
  refreshTokin() {}
}
