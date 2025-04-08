import {
    ClassSerializerInterceptor,
    Controller,
    Delete,
    Get,
    Param,
    ParseUUIDPipe,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UserResponse } from './resonse';
import { CurrentUser, Public, Roles } from '@common/common/decarators';
import { JwtPayload } from '@auth/interfaces';
import { RolesGuard } from '@auth/guards/role.guard';
import { Role } from '@prisma/client';

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

    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Get('profile/me')
    me(@CurrentUser() CurrentUser: JwtPayload) {
        console.log(CurrentUser);
        return CurrentUser;
    }
}
