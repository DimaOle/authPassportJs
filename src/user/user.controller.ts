import {
    ClassSerializerInterceptor,
    Controller,
    Delete,
    Get,
    Param,
    ParseUUIDPipe,
    UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UserResponse } from './resonse';
import { CurrentUser } from '@common/common/decarators';
import { JwtPayload } from '@auth/interfaces';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @UseInterceptors(ClassSerializerInterceptor)
    @Get(':idOrEmail')
    async findOneUser(@Param('idOrEmail') idOrEmail: string) {
        const user = await this.userService.findOne(idOrEmail);
        return new UserResponse(user);
    }

    @UseInterceptors(ClassSerializerInterceptor)
    @Delete(':id')
    deleteUser(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() currentUser: JwtPayload) {
        return this.userService.delete(id, currentUser);
    }
}
