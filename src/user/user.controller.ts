import {
    Body,
    ClassSerializerInterceptor,
    Controller,
    Delete,
    Get,
    Param,
    ParseUUIDPipe,
    Post,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UserResponse } from './resonse';
import { CurrentUser, Public, Roles } from '@common/common/decarators';
import { JwtPayload } from '@auth/interfaces';
import { RolesGuard } from '@auth/guards/role.guard';
import { Role } from '@prisma/client';
import { UpdateUserDto } from './dto';
import { UpdateUserGuard } from './guards';

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
        return CurrentUser;
    }

    @UseGuards(UpdateUserGuard)
    @Post('profile/update')
    updateUser(@Body() dto: UpdateUserDto) {
        return this.userService.update(dto);
    }
}
