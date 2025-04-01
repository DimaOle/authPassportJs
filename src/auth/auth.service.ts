import { BadRequestException } from '@nestjs/common';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Token } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { UserService } from '@user/user.service';
import { compareSync } from 'bcrypt';
import { add } from 'date-fns';
import { v4 } from 'uuid';
import { LoginDto, RegisterDto } from './dto';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name)
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly prismaServise: PrismaService
    ) {}
    
    async register(dto: RegisterDto) {
        const user = this.userService.save(dto).catch(err => {
            this.logger.error(err)
            return null
        })
        if (!user) {
             throw new BadRequestException(`Unable to register user with data ${JSON.stringify(dto)}`)
        }
        return user
    }

    async login(dto: LoginDto) {
        const user = await this.userService.findOne(dto.email).catch(err => {
            this.logger.error(err)
            return null
        })

        if (!user || !compareSync(dto.password, user.password)) {
            throw new UnauthorizedException("Incorrectly password or email")
        }

        const accessToken = this.jwtService.sign({
            id: user.id,
            email: user.email,
            roles: user.roles
        })

        const refreshToken = await this.getRefreshToken(user.id)

        if (!refreshToken) {
            throw new BadRequestException(`I can't log in with the data that was transferred ${JSON.stringify(dto)}`)
        };

        return {accessToken, refreshToken}
    }

    private async getRefreshToken(userId: string): Promise<Token> {
        return this.prismaServise.token.create({
            data: {
                token: v4(),
                exp: add(new Date(), { months: 1 }),
                userId,
            }
        })
    }
}
