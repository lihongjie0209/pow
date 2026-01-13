package cn.lihongjie.pow.core;

import cn.lihongjie.pow.client.PowChallengeSolver;
import cn.lihongjie.pow.exception.PowException;
import cn.lihongjie.pow.model.PowChallenge;
import cn.lihongjie.pow.model.PowSolution;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * PowChallengeVerifier Context 验证测试
 * 
 * 测试场景：
 * 1. Context 一致性验证通过
 * 2. Context 字段缺失检测
 * 3. Context 值不匹配检测
 * 4. 标准字段过滤测试
 * 5. 空 context 兼容性
 */
public class PowChallengeVerifierContextTest {
    
    private static final Logger log = LoggerFactory.getLogger(PowChallengeVerifierContextTest.class);
    
    private static final String SECRET = "your-256-bit-secret-key-min-32chars!!";
    
    private PowChallengeGenerator generator;
    private PowChallengeVerifier verifier;
    private PowChallengeSolver solver;
    
    @Before
    public void setup() {
        generator = new PowChallengeGenerator(SECRET);
        verifier = new PowChallengeVerifier(SECRET, new PowChallengeVerifier.ReplayProtection() {
            private final java.util.Set<String> usedJtis = new java.util.HashSet<>();
            
            @Override
            public boolean isUsed(String jti) {
                return usedJtis.contains(jti);
            }
            
            @Override
            public void markAsUsed(String jti, long expiration) {
                usedJtis.add(jti);
            }
        });
        solver = new PowChallengeSolver();
    }
    
    @Test
    public void testContextValidationSuccess() {
        log.info("=== Test: Context Validation Success ===");
        
        // 1. 生成带 context 的 challenge
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "user_12345");
        context.put("apiPath", "/api/payment");
        context.put("amount", 1000);
        
        PowChallenge challenge = generator.generate(100.0, context);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken());
        
        // 3. 服务端验证（带 context）
        boolean valid = verifier.verify(solution, context);
        
        assertTrue("Context validation should pass", valid);
        log.info("✓ Context validation SUCCESS with userId={}, apiPath={}, amount={}", 
                context.get("userId"), context.get("apiPath"), context.get("amount"));
        log.info("=== Test PASSED ===\n");
    }
    
    @Test
    public void testContextMissingField() {
        log.info("=== Test: Context Missing Field Detection ===");
        
        // 1. 生成带部分 context 的 challenge
        Map<String, Object> generationContext = new HashMap<>();
        generationContext.put("userId", "user_12345");
        
        PowChallenge challenge = generator.generate(100.0, generationContext);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken());
        
        // 3. 验证时要求额外的字段
        Map<String, Object> validationContext = new HashMap<>();
        validationContext.put("userId", "user_12345");
        validationContext.put("apiPath", "/api/payment"); // 这个字段不存在
        
        try {
            verifier.verify(solution, validationContext);
            fail("Should throw PowException for missing field");
        } catch (PowException e) {
            assertTrue("Error message should mention missing field", 
                    e.getMessage().contains("missing field"));
            log.info("✓ Correctly detected missing field: {}", e.getMessage());
        }
        
        log.info("=== Test PASSED ===\n");
    }
    
    @Test
    public void testContextValueMismatch() {
        log.info("=== Test: Context Value Mismatch Detection ===");
        
        // 1. 生成带 context 的 challenge
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "user_12345");
        context.put("amount", 1000);
        
        PowChallenge challenge = generator.generate(100.0, context);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken());
        
        // 3. 验证时提供不同的值
        Map<String, Object> wrongContext = new HashMap<>();
        wrongContext.put("userId", "user_12345");
        wrongContext.put("amount", 2000); // 不同的金额
        
        try {
            verifier.verify(solution, wrongContext);
            fail("Should throw PowException for value mismatch");
        } catch (PowException e) {
            assertTrue("Error message should mention mismatch", 
                    e.getMessage().contains("mismatch"));
            log.info("✓ Correctly detected value mismatch: {}", e.getMessage());
        }
        
        log.info("=== Test PASSED ===\n");
    }
    
    @Test
    public void testReservedFieldsFiltered() {
        log.info("=== Test: Reserved Fields Filtered ===");
        
        // 1. 尝试在 context 中覆盖标准字段
        Map<String, Object> maliciousContext = new HashMap<>();
        maliciousContext.put("userId", "user_12345");
        maliciousContext.put("jti", "malicious-jti");  // 尝试覆盖 JTI
        maliciousContext.put("exp", 9999999999L);      // 尝试覆盖过期时间
        maliciousContext.put("tgt", "0000000000000000"); // 尝试覆盖 target
        
        PowChallenge challenge = generator.generate(100.0, maliciousContext);
        
        // 2. 验证 JWT 中的标准字段未被覆盖
        String token = challenge.getToken();
        io.jsonwebtoken.Claims claims = io.jsonwebtoken.Jwts.parserBuilder()
                .setSigningKey(io.jsonwebtoken.security.Keys.hmacShaKeyFor(SECRET.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
        
        // 3. 检查标准字段是否正确
        assertNotEquals("JTI should not be overridden", "malicious-jti", claims.get("jti"));
        assertNotEquals("EXP should not be overridden", 9999999999L, claims.get("exp", Long.class).longValue());
        assertNotEquals("TGT should not be overridden", "0000000000000000", claims.get("tgt"));
        
        // 4. 检查合法字段是否存在
        assertEquals("userId should be present", "user_12345", claims.get("userId"));
        
        log.info("✓ Reserved fields protected: jti={}, exp={}, tgt={}", 
                claims.get("jti"), claims.get("exp"), claims.get("tgt", String.class).substring(0, 16));
        log.info("✓ User field preserved: userId={}", claims.get("userId"));
        log.info("=== Test PASSED ===\n");
    }
    
    @Test
    public void testEmptyContextCompatibility() {
        log.info("=== Test: Empty Context Compatibility ===");
        
        // 测试1: 验证时也不提供 context
        PowChallenge challenge1 = generator.generate(100.0, null);
        PowSolution solution1 = solver.solve(challenge1.getToken());
        boolean valid1 = verifier.verify(solution1, null);
        assertTrue("Verification without context should pass", valid1);
        
        // 测试2: 验证时提供空 Map（使用新的 challenge）
        PowChallenge challenge2 = generator.generate(100.0, null);
        PowSolution solution2 = solver.solve(challenge2.getToken());
        boolean valid2 = verifier.verify(solution2, new HashMap<>());
        assertTrue("Verification with empty context should pass", valid2);
        
        log.info("✓ Empty context compatibility verified");
        log.info("=== Test PASSED ===\n");
    }
    
    @Test
    public void testPartialContextMatch() {
        log.info("=== Test: Partial Context Match ===");
        
        // 1. 生成带多个字段的 context
        Map<String, Object> generationContext = new HashMap<>();
        generationContext.put("userId", "user_12345");
        generationContext.put("apiPath", "/api/payment");
        generationContext.put("amount", 1000);
        generationContext.put("currency", "USD");
        
        PowChallenge challenge = generator.generate(100.0, generationContext);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken());
        
        // 3. 验证时只检查部分字段
        Map<String, Object> validationContext = new HashMap<>();
        validationContext.put("userId", "user_12345");
        validationContext.put("amount", 1000);
        
        boolean valid = verifier.verify(solution, validationContext);
        assertTrue("Partial context validation should pass", valid);
        
        log.info("✓ Partial context match verified (2/4 fields checked)");
        log.info("=== Test PASSED ===\n");
    }
    
    @Test
    public void testRealWorldApiProtection() {
        log.info("=== Test: Real World API Protection ===");
        
        // 模拟 API 限流场景：同一用户对同一接口的请求
        String userId = "premium_user_001";
        String apiPath = "/api/v1/data/export";
        String sessionId = "sess_abc123";
        
        // 1. 服务端生成 challenge（绑定用户和接口）
        Map<String, Object> context = new HashMap<>();
        context.put("userId", userId);
        context.put("apiPath", apiPath);
        context.put("sessionId", sessionId);
        context.put("timestamp", System.currentTimeMillis());
        
        PowChallenge challenge = generator.generate(1000.0, context);
        log.info("Server issued challenge for API protection: userId={}, apiPath={}", 
                userId, apiPath);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken());
        log.info("Client solved challenge with nonce={}", solution.getNonce());
        
        // 3. 服务端验证（必须匹配用户和接口）
        Map<String, Object> validationContext = new HashMap<>();
        validationContext.put("userId", userId);
        validationContext.put("apiPath", apiPath);
        validationContext.put("sessionId", sessionId);
        
        boolean valid = verifier.verify(solution, validationContext);
        assertTrue("API protection verification should pass", valid);
        
        log.info("✓ API access authorized for user={}, path={}", userId, apiPath);
        
        // 4. 测试会话劫持场景（不同 sessionId）
        Map<String, Object> hijackContext = new HashMap<>();
        hijackContext.put("userId", userId);
        hijackContext.put("apiPath", apiPath);
        hijackContext.put("sessionId", "sess_hijacked");
        
        try {
            verifier.verify(solution, hijackContext);
            fail("Should detect session hijacking");
        } catch (PowException e) {
            log.info("✓ Session hijacking detected: {}", e.getMessage());
        }
        
        log.info("=== Test PASSED ===\n");
    }
}
