import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const REFRESH_TOKEN = 'refreshtoken'

export const Cookie = createParamDecorator((key: string, ctx: ExecutionContext) => {
    const requset = ctx.switchToHttp().getRequest();
    return  key && requset.cookies && requset.cookies[key] ? requset.cookies[key] : undefined
})