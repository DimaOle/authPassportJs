import { ForbiddenException, Injectable } from '@nestjs/common';
import { Role, User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from '@auth/interfaces';

@Injectable()
export class UserService {
    constructor(private readonly prismaService: PrismaService) {}

    async save(user: Partial<User>) {
        const hashedPassword = this.hashPassword(user.password);
        return await this.prismaService.user.create({
            data: {
                email: user.email,
                password: hashedPassword,
                roles: ['USER'],
            },
        });
    }

    async findOne(idOrEmail: string) {
        return await this.prismaService.user.findFirst({
            where: {
                OR: [{ id: idOrEmail }, { email: idOrEmail }],
            },
        });
    }

    async delete(id: string, currentUser: JwtPayload) {
        console.log(currentUser);
        if (currentUser.id !== id && !currentUser.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException();
        }
        return await this.prismaService.user.delete({
            where: {
                id: id,
            },
            select: {
                id: true,
            },
        });
    }

    private hashPassword(password: string) {
        return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
    }
}
