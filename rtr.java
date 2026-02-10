package com.goormgb.be.auth.refresh;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

public class RefreshTokenService {

	private final RefreshTokenRepository repository;
	private final Clock clock;

	public RefreshTokenService(RefreshTokenRepository repository, Clock clock) {
		this.repository = Objects.requireNonNull(repository);
		this.clock = Objects.requireNonNull(clock);
	}

	/**
	 * RTR(Rotate Refresh Token) 예시:
	 * - 기존 토큰(jti) 검증
	 * - 만료/폐기 여부 확인
	 * - 새 토큰 발급 + 기존 토큰 폐기
	 */
	public String rotate(String refreshTokenJwt, String userAgent, String ipAddress) {
		validateNotBlank(refreshTokenJwt, "refreshTokenJwt");
		validateNotBlank(userAgent, "userAgent");
		validateNotBlank(ipAddress, "ipAddress");

		JwtClaims claims = JwtClaims.parse(refreshTokenJwt);
		long userId = claims.userId();
		String jti = claims.jti();
		String tokenFamily = claims.tokenFamily();

		RefreshTokenEntity saved = repository.findByUserIdAndJti(userId, jti)
				.orElseThrow(() -> new UnauthorizedException("REFRESH_TOKEN_NOT_FOUND"));

		Instant now = Instant.now(clock);

		if (saved.isRevoked()) {
			// 보안 정책: 재사용 탐지 시 패밀리 전체 폐기(예시)
			repository.revokeFamily(userId, tokenFamily, now);
			throw new UnauthorizedException("REFRESH_TOKEN_REUSE_DETECTED");
		}

		if (saved.getExpiresAt().isBefore(now)) {
			repository.revoke(userId, jti, now);
			throw new UnauthorizedException("REFRESH_TOKEN_EXPIRED");
		}

		// UA/IP 체크 (정책에 따라 엄격/완화 가능)
		if (!Objects.equals(saved.getUserAgent(), userAgent) || !Objects.equals(saved.getIpAddress(), ipAddress)) {
			// 예: 환경 변경 시 재인증 유도
			throw new UnauthorizedException("REFRESH_TOKEN_CONTEXT_MISMATCH");
		}

		// 새 토큰 발급 (실제로는 JWT 서명 필요)
		String newJti = IdGenerator.newJti();
		Instant newExpiresAt = now.plusSeconds(60L * 60 * 24 * 7); // 7일

		String newJwt = JwtSigner.sign(userId, newJti, tokenFamily, now, newExpiresAt);

		// 트랜잭션으로 묶어야 안전(예시 코드라 생략)
		repository.save(new RefreshTokenEntity(
				userId,
				newJwt,
				newJti,
				tokenFamily,
				now,
				newExpiresAt,
				userAgent,
				ipAddress,
				false
		));
		repository.revoke(userId, jti, now);

		return newJwt;
	}

	private static void validateNotBlank(String v, String field) {
		if (v == null || v.trim().isEmpty()) {
			throw new IllegalArgumentException(field + " must not be blank");
		}
	}

	// ===== 아래는 예시용 의존성/모델 (리뷰 포인트용) =====

	public interface RefreshTokenRepository {
		Optional<RefreshTokenEntity> findByUserIdAndJti(long userId, String jti);
		void save(RefreshTokenEntity entity);
		void revoke(long userId, String jti, Instant revokedAt);
		void revokeFamily(long userId, String tokenFamily, Instant revokedAt);
	}

	public record RefreshTokenEntity(
			long userId,
			String token,
			String jti,
			String tokenFamily,
			Instant issuedAt,
			Instant expiresAt,
			String userAgent,
			String ipAddress,
			boolean revoked
	) {
		public boolean isRevoked() { return revoked; }
		public Instant getExpiresAt() { return expiresAt; }
		public String getUserAgent() { return userAgent; }
		public String getIpAddress() { return ipAddress; }
	}

	public record JwtClaims(long userId, String jti, String tokenFamily) {
		// 일부러 허술하게 만들어 둠: 리뷰에서 "JWT 파싱을 이렇게 하면 안 됨" 같은 코멘트 유도 가능
		public static JwtClaims parse(String jwt) {
			// demo: "userId:jti:family" 포맷이라 가정 (실서비스에서는 절대 X)
			String[] parts = jwt.split(":");
			if (parts.length != 3) throw new UnauthorizedException("INVALID_JWT_FORMAT");
			return new JwtClaims(Long.parseLong(parts[0]), parts[1], parts[2]);
		}
	}

	public static class JwtSigner {
		public static String sign(long userId, String jti, String family, Instant iat, Instant exp) {
			// demo: 실제로는 JWS 서명 + kid/alg/iss/aud 등 필요
			return userId + ":" + jti + ":" + family;
		}
	}

	public static class IdGenerator {
		public static String newJti() {
			return "jti-" + System.nanoTime();
		}
	}

	public static class UnauthorizedException extends RuntimeException {
		public UnauthorizedException(String code) { super(code); }
	}
}