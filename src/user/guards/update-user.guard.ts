import { CanActivate, ExecutionContext, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { UpdateUserDto } from '@user/dto';

@Injectable()
export class UpdateUserGuard implements CanActivate {
    constructor(private prismaService: PrismaService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const user: User = request.user;
        const dto: UpdateUserDto = request.body;

        const targetUser = await this.prismaService.user.findFirst({ where: { id: dto.id } });

        if (!targetUser) {
            throw new NotFoundException(`User with id ${dto.id} not found`);
        }

        if (user.id !== dto.id && !user.roles.includes('ADMIN')) {
            throw new ForbiddenException('You do not have access to this resource');
        }
        console.log(user);
        console.log(dto);
        return true;
    }
}
