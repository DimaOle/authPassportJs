import { BadRequestException, HttpStatus } from '@nestjs/common';
import { ConflictException } from '@nestjs/common';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Token, User } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { UserService } from '@user/user.service';
import { compareSync } from 'bcrypt';
import { Response } from 'express';
import { add } from 'date-fns';
import { v4 } from 'uuid';
import { LoginDto, RegisterDto } from './dto';
import { Tokens } from './interfaces';
import { ConfigService } from '@nestjs/config';
import { REFRESH_TOKEN } from '@common/common/decarators';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name)
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly prismaServise: PrismaService,
        private readonly configService: ConfigService
    ) {}
    
    async register(dto: RegisterDto) {
        const user = await this.userService.findOne(dto.email);

        if (user) {
            throw new ConflictException(`A user with this email has already been created`)
        }

        const createUser = await this.userService.save(dto).catch(err => {
            this.logger.error(err)
            return null
        })

        if (!createUser) {
             throw new BadRequestException(`Unable to register user with data ${JSON.stringify(dto)}`)
        }
        return createUser
    }
    
    async refreshTokens(refreshToken: string): Promise<Tokens> {
        const token = await this.prismaServise.token.findUnique({ where: { token: refreshToken } })
        if (!token) {
            throw new UnauthorizedException()
        }
        await this.prismaServise.token.delete({ where: { token: refreshToken } });

        if (new Date(token.exp) < new Date()) {
            throw new UnauthorizedException()
        }
        const users = await this.userService.findOne(token.userId);

        return this.generateTokens(users);
    }
    async login(dto: LoginDto): Promise<Tokens> {
        const user = await this.userService.findOne(dto.email).catch(err => {
            this.logger.error(err);
            return null
        })

        if (!user || !compareSync(dto.password, user.password)) {
            throw new UnauthorizedException("Incorrectly password or email")
        }
        return this.generateTokens(user);

    }

    private async generateTokens(user: User): Promise<Tokens> {
        const accessToken = 'Bearer ' + this.jwtService.sign({
            id: user.id,
            email: user.email,
            roles: user.roles
        })

        const refreshToken = await this.getRefreshToken(user.id)

        if (!refreshToken) {
            throw new BadRequestException(`I can't log in with the data that was transferred`)
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
      
    setRefreshTokenToCookies(tokens: Tokens, res: Response) {
    if (!tokens) {
      throw new UnauthorizedException();
    }

    res.cookie(REFRESH_TOKEN, tokens.refreshToken.token, {
      httpOnly: true,
      sameSite: 'lax',
      expires: new Date(tokens.refreshToken.exp),
      secure: this.configService.get('NODE_ENV', 'develompment') === 'production',
      path: '/'
    })
    
    res.status(HttpStatus.CREATED).json({accessToken: tokens.accessToken})
  }
    
}
