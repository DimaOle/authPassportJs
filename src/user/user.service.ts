import {
    BadRequestException,
    ForbiddenException,
    HttpException,
    HttpStatus,
    Inject,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { Providers, Role, User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from '@auth/interfaces';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ConfigService } from '@nestjs/config';
import { convertToSecondsUtil } from '@common/common/utils';
import { UpdateUserDto } from './dto';

@Injectable()
export class UserService {
    constructor(
        private readonly prismaService: PrismaService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private readonly configService: ConfigService,
    ) {}

    async save(user: Partial<User>) {
        const hashedPassword = user?.password ? this.hashPassword(user.password) : null;
        return await this.prismaService.user.create({
            data: {
                email: user.email,
                password: hashedPassword,
                roles: ['USER'],
                provider: user.provider ? user.provider : null,
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

    async update(dto: UpdateUserDto) {
        const user = await this.prismaService.user.findFirst({ where: { id: dto.id } });
        if (!user) {
            throw new NotFoundException('User with id 1 not found');
        }

        if (dto.id !== user.id && user.roles.includes('ADMIN')) {
            throw new ForbiddenException('You do not have access to this resource');
        }

        if (dto.password && dto.password !== dto.repeatPassword) {
            throw new BadRequestException('Passwords do not match');
        }
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
