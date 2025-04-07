import { Role, User } from '@prisma/client';
import { Exclude } from 'class-transformer';

export class UserResponse implements User {
    id: string;
    email: string;

    @Exclude()
    password: string;

    @Exclude()
    createAt: Date;
    updateAt: Date;
    roles: Role[];

    constructor(user: User) {
        Object.assign(this, user);
    }
}
