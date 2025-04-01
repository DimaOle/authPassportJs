import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from 'src/user/user.module';
import { option } from './config';


@Module({
  controllers: [AuthController],
  imports: [PassportModule, JwtModule.registerAsync(option()), UserModule],
  providers: [AuthService],
})
export class AuthModule {}
