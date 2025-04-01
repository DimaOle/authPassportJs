import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) { }
  
  @Post('login')
  login(@Body() dto: LoginDto) { }
  
  @Get('refresh')
  refreshTokin() {}
}
