import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpException,
  HttpStatus,
  Logger,
  Post,
  Req,
  ServiceUnavailableException,
  UseGuards,
} from '@nestjs/common';
import { IsBase64 } from 'class-validator';
import type { Request } from 'express';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { AttestedGuard } from '../attest/attested.guard';
import { CurrentUser, AuthUser } from '../auth/current-user.decorator';
import { ConnectionService, ConnectError } from './connection.service';

class ConnectDto {
  // The ephemeral X25519 public key. The AttestedGuard has already proven this
  // equals the device's attested_client_public_key before we get here.
  @IsBase64()
  clientPublicKey!: string;
}

@Controller()
export class ConnectionController {
  private readonly log = new Logger(ConnectionController.name);

  constructor(private readonly connection: ConnectionService) {}

  /**
   * POST /connect — the convergence point. Behind JwtAuthGuard (verified
   * principal) AND AttestedGuard (attested device + key binding enforced).
   *
   * Returns the encrypted payload for PREMIUM (active now); for FREE it returns
   * the ad grant + nonce (the encrypted payload is delivered by verify-ad-reward
   * after the 2 ads are server-verified — Provisioning Model). Never returns a
   * cleartext address/config.
   */
  @UseGuards(JwtAuthGuard, AttestedGuard)
  @HttpCode(200)
  @Post('connect')
  async connect(@CurrentUser() user: AuthUser, @Body() _dto: ConnectDto, @Req() req: Request) {
    // The guard attached the canonical attested key; prefer it over the body.
    const clientPubKey = (req as unknown as { attestedClientPublicKey?: Buffer }).attestedClientPublicKey;
    if (!clientPubKey || clientPubKey.length !== 32) {
      // Should be unreachable behind AttestedGuard, but fail closed.
      throw new BadRequestException('missing attested key');
    }

    try {
      return await this.connection.connect({
        userId: user.userId,
        deviceId: user.deviceId,
        clientPubKey,
      });
    } catch (e) {
      if (e instanceof ConnectError) {
        // Provisioning/capacity problems are transient → 503 (client retries).
        this.log.warn(`connect failed (${e.reason}) for user ${user.userId}`);
        throw new ServiceUnavailableException(e.reason);
      }
      if (e instanceof HttpException) throw e; // e.g. unique-violation surfaced upstream
      // A unique-violation on the one-live-session-per-device index → 409.
      if (isUniqueViolation(e)) {
        throw new HttpException('a session is already active for this device', HttpStatus.CONFLICT);
      }
      this.log.error(`connect error for user ${user.userId}: ${(e as Error).message}`);
      throw new ServiceUnavailableException('connect_failed');
    }
  }
}

function isUniqueViolation(e: unknown): boolean {
  return typeof e === 'object' && e !== null && (e as { code?: string }).code === '23505';
}
