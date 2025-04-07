import {
    Body,
    ClassSerializerInterceptor,
    Controller,
    Delete,
    Get,
    Param,
    ParseUUIDPipe,
    Post,
    UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UserResponse } from './resonse';
import { Public } from '@common/common/decarators';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Public()
    @UseInterceptors(ClassSerializerInterceptor)
    @Post()
    async createUser(@Body() dto) {
        const user = await this.userService.save(dto);
        return new UserResponse(user);
    }

    @UseInterceptors(ClassSerializerInterceptor)
    @Get(':idOrEmail')
    async findOneUser(@Param('idOrEmail') idOrEmail: string) {
        const user = await this.userService.findOne(idOrEmail);
        return new UserResponse(user);
    }

    @UseInterceptors(ClassSerializerInterceptor)
    @Delete(':id')
    deleteUser(@Param('id', ParseUUIDPipe) id: string) {
        return this.userService.delete(id);
    }
}
