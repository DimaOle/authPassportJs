import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { Role, User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from '@auth/interfaces';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ConfigService } from '@nestjs/config';
import { convertToSecondsUtil } from '@common/common/utils';

@Injectable()
export class UserService {
    constructor(
        private readonly prismaService: PrismaService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private readonly configService: ConfigService,
    ) {}

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

    async findOne(idOrEmail: string, isReset = false) {
        if (isReset) {
            await this.cacheManager.del(idOrEmail);
        }
        const user = await this.cacheManager.get<User>(idOrEmail);
        if (!user) {
            const user = await this.prismaService.user.findFirst({
                where: {
                    OR: [{ id: idOrEmail }, { email: idOrEmail }],
                },
            });

            if (!user) {
                return null;
            }
            const ttl = convertToSecondsUtil(this.configService.get('JWT_EXP'));
            await this.cacheManager.set(idOrEmail, user, ttl);
            return user;
        }

        return user;
    }

    async delete(id: string, currentUser: JwtPayload) {
        console.log(currentUser);
        if (currentUser.id !== id && !currentUser.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException();
        }
        await Promise.all([this.cacheManager.del(id), this.cacheManager.del(currentUser.email)]);
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
