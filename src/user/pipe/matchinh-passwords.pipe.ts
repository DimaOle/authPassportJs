import { ArgumentMetadata, BadRequestException, Injectable, PipeTransform } from '@nestjs/common';

@Injectable()
export class MatchPasswordsPipe implements PipeTransform {
    transform(value: any, metadata: ArgumentMetadata) {
        if (value.password !== value.repeatPassword) {
            throw new BadRequestException('Passwords do not match');
        }
        return value;
    }
}
