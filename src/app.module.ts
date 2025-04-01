
import { Module } from '@nestjs/common';
import { PrismaModule } from './prisma/prisma.module';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';


@Module({
    imports: [UserModule, PrismaModule, AuthModule, ConfigModule.forRoot({isGlobal: true})],
    providers: []
})
export class AppModule {}