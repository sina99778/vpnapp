import { Body, Controller, HttpCode, Post, UseGuards } from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';
import { AdminAuthService } from './admin-auth.service';

class AdminLoginDto {
  @IsEmail()
  @MaxLength(254)
  email!: string;

  @IsString()
  @MinLength(1)
  @MaxLength(128)
  password!: string;
}

/**
 * PUBLIC admin login (it IS the authentication, so no JwtAuthGuard/AdminGuard).
 * Rate-limited like the VPN login.
 */
@Controller('admin/auth')
@UseGuards(ThrottlerGuard)
export class AdminAuthController {
  constructor(private readonly adminAuth: AdminAuthService) {}

  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @HttpCode(200)
  @Post('login')
  login(@Body() dto: AdminLoginDto) {
    return this.adminAuth.login(dto.email, dto.password);
  }
}
