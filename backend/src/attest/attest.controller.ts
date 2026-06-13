import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  Logger,
  Post,
  Req,
  ServiceUnavailableException,
  UseGuards,
} from '@nestjs/common';
import { IsBase64, IsIn, IsOptional, IsString, IsUUID, ValidateNested, IsObject } from 'class-validator';
import { Type } from 'class-transformer';
import type { Request } from 'express';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../auth/current-user.decorator';
import { AttestService, AttestationPayload, Platform } from './attest.service';
import { AttestationError } from './attest.config';

class AttestationDto {
  @IsIn(['android', 'ios'])
  platform!: Platform;

  // android
  @IsOptional() @IsString()
  integrityToken?: string;

  // ios
  @IsOptional() @IsIn(['attest', 'assert'])
  mode?: 'attest' | 'assert';
  @IsOptional() @IsString()
  keyId?: string;
  @IsOptional() @IsString()
  attestation?: string;
  @IsOptional() @IsString()
  assertion?: string;
}

class VerifyDto {
  @IsUUID()
  challengeId!: string;

  // Base64 of the 32-byte X25519 public key (same one sent to /connect).
  @IsBase64()
  clientPublicKey!: string;

  @IsObject()
  @ValidateNested()
  @Type(() => AttestationDto)
  attestation!: AttestationDto;
}

@Controller('device/attest')
export class AttestController {
  private readonly log = new Logger(AttestController.name);

  constructor(private readonly attest: AttestService) {}

  /** Issue a one-time challenge bound to the authenticated device. */
  @UseGuards(JwtAuthGuard)
  @Post('challenge')
  async challenge(@CurrentUser() user: AuthUser) {
    return this.attest.createChallenge(user.deviceId);
  }

  /**
   * Verify the attestation and (on success) flip devices.is_attested.
   * 403 on a rejected attestation; 503 only on transient upstream failure
   * (which never grants attestation, so it is safe to let the client retry).
   */
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  @Post('verify')
  async verify(@CurrentUser() user: AuthUser, @Body() dto: VerifyDto, @Req() req: Request) {
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || null;
    const platform = dto.attestation.platform;
    const payload = this.toPayload(dto.attestation);

    try {
      await this.attest.verify({
        deviceId: user.deviceId,
        challengeId: dto.challengeId,
        clientPubKey: Buffer.from(dto.clientPublicKey, 'base64'),
        attestation: payload,
      });
      await this.attest.audit(user.deviceId, platform, 'passed', null, ip);
      return { attested: true };
    } catch (err) {
      if (err instanceof AttestationError) {
        await this.attest.audit(user.deviceId, platform, 'rejected', err.reason, ip);
        // ONLY a genuinely transient upstream failure → 503 (retryable, never
        // grants). Every validation/verdict failure (incl. a forged token) → 403.
        if (err.reason === 'transient') {
          throw new ServiceUnavailableException('attestation temporarily unavailable');
        }
        this.log.warn(`attestation rejected for device ${user.deviceId}: ${err.reason}`);
        throw new ForbiddenException('attestation failed');
      }
      // Unknown error → fail closed as 403, audited.
      await this.attest.audit(user.deviceId, platform, 'rejected', 'internal_error', ip);
      this.log.error(`attestation error: ${(err as Error).message}`);
      throw new ForbiddenException('attestation failed');
    }
  }

  private toPayload(a: AttestationDto): AttestationPayload {
    if (a.platform === 'android') {
      if (!a.integrityToken) throw new ForbiddenException('missing integrityToken');
      return { platform: 'android', integrityToken: a.integrityToken };
    }
    if (!a.mode || !a.keyId) throw new ForbiddenException('missing ios attestation fields');
    return {
      platform: 'ios',
      mode: a.mode,
      keyId: a.keyId,
      attestation: a.attestation,
      assertion: a.assertion,
    };
  }
}
