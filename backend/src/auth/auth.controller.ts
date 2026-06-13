import { Body, Controller, HttpCode, Post, UseGuards } from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { IsEmail, IsIn, IsOptional, IsString, Length, MaxLength, MinLength } from 'class-validator';
import { JwtAuthGuard } from './jwt-auth.guard';
import { CurrentUser, AuthUser } from './current-user.decorator';
import { AuthService, Platform } from './auth.service';

class DeviceFields {
  @IsIn(['android', 'ios'])
  platform!: Platform;

  @IsString()
  @Length(8, 128)
  installId!: string;

  @IsOptional()
  @IsString()
  @MaxLength(40)
  appVersion?: string;
}

class AnonDto extends DeviceFields {}

class RegisterDto {
  @IsEmail()
  @MaxLength(254)
  email!: string;

  @IsString()
  @MinLength(12) // NIST 800-63B high-assurance guidance
  @MaxLength(128)
  password!: string;
}

class LoginDto extends DeviceFields {
  @IsEmail()
  @MaxLength(254)
  email!: string;

  @IsString()
  @MinLength(1)
  @MaxLength(128)
  password!: string;
}

class RefreshDto {
  @IsString()
  @Length(16, 256)
  refreshToken!: string;
}

/**
 * Identity distribution. Throttled per-IP (ThrottlerGuard at class level); the
 * account-creating / credential routes get tighter @Throttle overrides. The
 * throttler is scoped HERE (not global) so high-volume routes like the AdMob SSV
 * callback are not rate-limited.
 */
@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  /** First launch — anonymous account. Strictly limited to deter DB spamming. */
  @Throttle({ default: { limit: 8, ttl: 60_000 } })
  @HttpCode(201)
  @Post('anon')
  anon(@Body() dto: AnonDto) {
    return this.auth.anon(dto);
  }

  /** Claim the current anonymous account with email + password. */
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  @Post('register')
  register(@CurrentUser() user: AuthUser, @Body() dto: RegisterDto) {
    return this.auth.register(user.userId, dto.email, dto.password);
  }

  /** Email/password login (per-user lockout in the service). */
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @HttpCode(200)
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.auth.login(dto);
  }

  /** Rotate tokens; reuse of an old token revokes the whole family. */
  @Throttle({ default: { limit: 30, ttl: 60_000 } })
  @HttpCode(200)
  @Post('refresh')
  refresh(@Body() dto: RefreshDto) {
    return this.auth.refresh(dto.refreshToken);
  }

  /**
   * Revoke the presented refresh token's family. Access-token protected so a
   * stolen refresh token alone can't be used to DoS-revoke a victim's family;
   * the service also checks the token belongs to the caller.
   */
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  @HttpCode(200)
  @Post('logout')
  logout(@CurrentUser() user: AuthUser, @Body() dto: RefreshDto) {
    return this.auth.logout(user.userId, dto.refreshToken);
  }
}
