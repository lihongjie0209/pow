package cn.lihongjie.pow.core;

import cn.lihongjie.pow.client.PowChallengeSolver;
import cn.lihongjie.pow.model.PowChallenge;
import cn.lihongjie.pow.model.PowSolution;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * 业务上下文参数测试
 */
public class PowChallengeGeneratorContextTest {
    
    private static final Logger log = LoggerFactory.getLogger(PowChallengeGeneratorContextTest.class);
    
    private static final String SECRET = "ThisIsAVerySecureSecretKeyForJWT1234567890";
    private PowChallengeGenerator generator;
    private PowChallengeVerifier verifier;
    private PowChallengeSolver solver;
    private SecretKey secretKey;

    @Before
    public void setUp() {
        generator = new PowChallengeGenerator(SECRET);
        verifier = new PowChallengeVerifier(SECRET, new PowChallengeVerifier.ReplayProtection() {
            @Override
            public boolean isUsed(String jti) {
                return false;
            }
            
            @Override
            public void markAsUsed(String jti, long expiration) {
                // No-op for testing
            }
        });
        solver = new PowChallengeSolver();
        secretKey = Keys.hmacShaKeyFor(SECRET.getBytes());
    }

    @Test
    public void testGenerateWithBusinessContext() {
        log.info("=== Test: Generate with Business Context ===");
        
        // 构建业务上下文
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "user_12345");
        context.put("apiPath", "/api/v1/sensitive-operation");
        context.put("clientIp", "192.168.1.100");
        context.put("sessionId", "sess_abcdef123456");
        
        // 生成包含上下文的 Challenge
        PowChallenge challenge = generator.generate(1000.0, context);
        
        assertNotNull(challenge);
        assertNotNull(challenge.getToken());
        
        // 解析 JWT 验证上下文参数
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(challenge.getToken())
                .getBody();
        
        // 验证标准字段
        assertNotNull(claims.get("iat"));
        assertNotNull(claims.get("exp"));
        assertNotNull(claims.get("jti"));
        assertNotNull(claims.get("salt"));
        assertNotNull(claims.get("tgt"));
        
        // 验证业务上下文
        assertEquals("user_12345", claims.get("userId"));
        assertEquals("/api/v1/sensitive-operation", claims.get("apiPath"));
        assertEquals("192.168.1.100", claims.get("clientIp"));
        assertEquals("sess_abcdef123456", claims.get("sessionId"));
        
        log.info("JWT Claims: {}", claims);
        log.info("=== Test PASSED ===");
    }

    @Test
    public void testSolveAndVerifyWithContext() {
        log.info("=== Test: Solve and Verify with Context ===");
        
        // 1. 生成包含用户 ID 的 Challenge
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "user_98765");
        context.put("action", "transfer");
        context.put("amount", 1000);
        
        PowChallenge challenge = generator.generate(100.0, context);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken(), 10_000_000);
        assertNotNull(solution);
        
        // 3. 服务端验证
        verifier.verify(solution);
        
        // 4. 验证业务上下文
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(solution.getToken())
                .getBody();
        
        assertEquals("user_98765", claims.get("userId"));
        assertEquals("transfer", claims.get("action"));
        assertEquals(1000, claims.get("amount"));
        
        log.info("Verification SUCCESS with context: userId={}, action={}, amount={}", 
                claims.get("userId"), claims.get("action"), claims.get("amount"));
        log.info("=== Test PASSED ===");
    }

    @Test
    public void testGenerateWithoutContext() {
        log.info("=== Test: Generate without Context (Backward Compatibility) ===");
        
        // 使用原始方法（无上下文）
        PowChallenge challenge = generator.generate(1000.0);
        
        assertNotNull(challenge);
        assertNotNull(challenge.getToken());
        
        // 验证只包含标准字段
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(challenge.getToken())
                .getBody();
        
        // 标准字段存在
        assertNotNull(claims.get("iat"));
        assertNotNull(claims.get("exp"));
        assertNotNull(claims.get("jti"));
        assertNotNull(claims.get("salt"));
        assertNotNull(claims.get("tgt"));
        
        // 业务上下文不存在
        assertNull(claims.get("userId"));
        assertNull(claims.get("apiPath"));
        
        log.info("JWT Claims (no context): {}", claims);
        log.info("=== Test PASSED ===");
    }

    @Test
    public void testContextWithNullAndEmpty() {
        log.info("=== Test: Context with null and empty map ===");
        
        // null 上下文
        PowChallenge challenge1 = generator.generate(100.0, null);
        assertNotNull(challenge1);
        
        // 空 Map
        PowChallenge challenge2 = generator.generate(100.0, new HashMap<>());
        assertNotNull(challenge2);
        
        log.info("=== Test PASSED ===");
    }

    @Test
    public void testRealWorldScenario() {
        log.info("=== Test: Real World Scenario - API Rate Limiting ===");
        
        // 模拟真实业务场景：API 限流 + PoW
        String userId = "premium_user_001";
        String endpoint = "/api/v1/data/export";
        String requestId = "req_" + System.currentTimeMillis();
        
        Map<String, Object> context = new HashMap<>();
        context.put("userId", userId);
        context.put("endpoint", endpoint);
        context.put("requestId", requestId);
        context.put("tier", "premium");
        context.put("rateLimit", 100); // 每分钟 100 次
        
        // 1. 服务端生成 Challenge
        PowChallenge challenge = generator.generate(1000.0, context);
        log.info("Server issued challenge for user: {}", userId);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken(), 10_000_000);
        log.info("Client solved challenge with nonce: {}", solution.getNonce());
        assertNotNull(solution);
        
        // 3. 服务端验证并提取上下文
        verifier.verify(solution);
        
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(solution.getToken())
                .getBody();
        
        // 4. 业务逻辑：根据上下文执行操作
        String claimUserId = claims.get("userId", String.class);
        String claimEndpoint = claims.get("endpoint", String.class);
        String claimTier = claims.get("tier", String.class);
        Integer claimRateLimit = claims.get("rateLimit", Integer.class);
        
        assertEquals(userId, claimUserId);
        assertEquals(endpoint, claimEndpoint);
        assertEquals("premium", claimTier);
        assertEquals(Integer.valueOf(100), claimRateLimit);
        
        log.info("✓ Authorized request for user={}, tier={}, limit={}/min", 
                claimUserId, claimTier, claimRateLimit);
        log.info("=== Test PASSED ===");
    }
}
