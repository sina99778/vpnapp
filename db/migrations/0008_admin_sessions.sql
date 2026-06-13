-- =============================================================================
-- Admin web sessions have NO VPN device (they never /connect and must not
-- pollute the devices table). Allow a refresh token to exist without a device.
-- The admin access JWT carries a nil-UUID `did` sentinel, which the AttestedGuard
-- rejects — so an admin token can never be used on a VPN route.
-- =============================================================================

alter table refresh_tokens alter column device_id drop not null;
