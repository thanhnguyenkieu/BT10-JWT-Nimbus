package vn.edu.hcmute.bt10;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;
import java.time.Duration;

/** Console exercise: issue a token, display claims, and reject a modified token. */
public final class JwtDemo {
    private JwtDemo() { }

    public static void main(String[] args) throws JOSEException, ParseException {
        // Demo-only key. In a real app load a random secret from environment/secret manager.
        JwtService jwtService = new JwtService(
                "BT10-demo-secret-change-this-32-bytes-minimum", Duration.ofMinutes(15));

        String token = jwtService.createToken("user-001", "nguyenvana", "USER");
        System.out.println("JWT được tạo:\n" + token);

        JWTClaimsSet claims = jwtService.verifyToken(token);
        System.out.println("\nXác minh thành công:");
        System.out.println("sub      = " + claims.getSubject());
        System.out.println("username = " + claims.getStringClaim("username"));
        System.out.println("role     = " + claims.getStringClaim("role"));
        System.out.println("issuer   = " + claims.getIssuer());
        System.out.println("expires  = " + claims.getExpirationTime());

        // Change the payload (rather than a trailing Base64URL character, which
        // can sometimes differ only in unused padding bits).
        String[] parts = token.split("\\.");
        String changedPayload = (parts[1].startsWith("A") ? "B" : "A") + parts[1].substring(1);
        String tampered = parts[0] + "." + changedPayload + "." + parts[2];
        try {
            jwtService.verifyToken(tampered);
            System.out.println("\nLỗi: token bị sửa nhưng vẫn được chấp nhận.");
        } catch (JOSEException | ParseException e) {
            System.out.println("\nToken bị sửa đã bị từ chối: " + e.getMessage());
        }
    }
}
