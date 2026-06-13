import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/** The verified principal attached by JwtAuthGuard. */
export interface AuthUser {
  userId: string;
  deviceId: string;
}

/** @CurrentUser() → the verified { userId, deviceId } from the access token. */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthUser => {
    return ctx.switchToHttp().getRequest<{ user: AuthUser }>().user;
  },
);
