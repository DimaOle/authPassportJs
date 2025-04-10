import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from 'src/user/user.module';
import { option } from './config';
import { STRATEGIES } from './strategies/inxdex';
import { GUARDS } from './guards';
import { HttpModule } from '@nestjs/axios';

@Module({
    controllers: [AuthController],
    imports: [PassportModule, JwtModule.registerAsync(option()), UserModule, HttpModule],
    providers: [AuthService, ...STRATEGIES, ...GUARDS],
})
export class AuthModule {}
