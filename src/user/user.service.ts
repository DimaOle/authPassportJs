import { Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';



@Injectable()
export class UserService {
    
    constructor(private readonly prismaService: PrismaService) { }
    
    save(user: Partial<User>) { 
        return this.prismaService.user.create({
            data: {
                email: user.email,
                password: user.password,
                roles: ["USER"],
            }}
        )
    }


    
    findOne() { }

    delete() { }
}
