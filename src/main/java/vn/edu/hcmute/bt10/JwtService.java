package vn.edu.hcmute.bt10;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/** Issues and validates signed JWTs using Nimbus JOSE + JWT and HS256. */
public final class JwtService {
    private static final JWSAlgorithm ALGORITHM = JWSAlgorithm.HS256;
    private static final String ISSUER = "bt10-hcmute";
    private final byte[] secret;
    private final Duration lifetime;

    /** HS256 requires a secret of at least 256 bits (32 UTF-8 bytes). */
    public JwtService(String secret, Duration lifetime) {
        if (secret == null || secret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("HS256 secret phải có ít nhất 32 byte.");
        }
        if (lifetime == null || lifetime.isZero() || lifetime.isNegative()) {
            throw new IllegalArgumentException("Thời hạn token phải lớn hơn 0.");
        }
        this.secret = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        this.lifetime = lifetime;
    }

    public String createToken(String userId, String username, String role) throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(userId)
                .audience("bt10-api")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(lifetime)))
                .jwtID(UUID.randomUUID().toString())
                .claim("username", username)
                .claim("role", role)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(ALGORITHM).type(com.nimbusds.jose.JOSEObjectType.JWT).build(), claims);
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    /** Parses, checks the algorithm and signature, then validates standard claims. */
    public JWTClaimsSet verifyToken(String token) throws ParseException, JOSEException {
        SignedJWT jwt = SignedJWT.parse(token);
        if (!ALGORITHM.equals(jwt.getHeader().getAlgorithm())) {
            throw new JOSEException("Thuật toán JWT không được chấp nhận.");
        }
        if (!jwt.verify(new MACVerifier(secret))) {
            throw new JOSEException("Chữ ký JWT không hợp lệ.");
        }
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        Date now = new Date();
        if (!ISSUER.equals(claims.getIssuer())) {
            throw new JOSEException("Issuer không hợp lệ.");
        }
        if (!claims.getAudience().contains("bt10-api")) {
            throw new JOSEException("Audience không hợp lệ.");
        }
        if (claims.getExpirationTime() == null || !now.before(claims.getExpirationTime())) {
            throw new JOSEException("JWT đã hết hạn hoặc thiếu thời điểm hết hạn.");
        }
        if (claims.getNotBeforeTime() != null && now.before(claims.getNotBeforeTime())) {
            throw new JOSEException("JWT chưa có hiệu lực.");
        }
        return claims;
    }
}
