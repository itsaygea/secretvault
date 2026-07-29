class SessionRevocationManager {
  private userRevocationTimestamps: Map<string, number> = new Map();

  revokeAllUserSessions(userId: string): void {
    this.userRevocationTimestamps.set(userId, Date.now());
  }

  isTokenRevoked(userId: string, tokenIssuedAtMs: number): boolean {
    const revokedAt = this.userRevocationTimestamps.get(userId);
    if (!revokedAt) return false;
    return tokenIssuedAtMs < revokedAt;
  }

  clear(): void {
    this.userRevocationTimestamps.clear();
  }
}

export const sessionRevocation = new SessionRevocationManager();
