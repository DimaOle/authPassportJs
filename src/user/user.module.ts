import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { CacheModule } from '@nestjs/cache-manager';

@Module({
    controllers: [UserController],
    providers: [UserService],
    exports: [UserService],
    imports: [CacheModule.register()],
})
export class UserModule {}
