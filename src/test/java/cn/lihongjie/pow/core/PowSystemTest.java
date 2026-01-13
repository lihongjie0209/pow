package cn.lihongjie.pow.core;

import cn.lihongjie.pow.client.PowChallengeSolver;
import cn.lihongjie.pow.exception.PowException;
import cn.lihongjie.pow.model.PowChallenge;
import cn.lihongjie.pow.model.PowSolution;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;

/**
 * JWT PoW 系统集成测试
 * 
 * @author lihongjie
 */
public class PowSystemTest {
    
    private static final Logger log = LoggerFactory.getLogger(PowSystemTest.class);
    
    private static final String SECRET_KEY = "ThisIsAVerySecureSecretKeyWith256Bits!!";
    
    private PowChallengeGenerator generator;
    private PowChallengeVerifier verifier;
    private PowChallengeSolver solver;

    @Before
    public void setUp() {
        generator = new PowChallengeGenerator(SECRET_KEY, 300_000L); // 5分钟
        verifier = new PowChallengeVerifier(SECRET_KEY, new InMemoryReplayProtection());
        solver = new PowChallengeSolver();
    }

    /**
     * 测试完整流程：生成 -> 求解 -> 验证
     */
    @Test
    public void testCompleteWorkflow() {
        log.info("=== Test: Complete Workflow ===");
        
        // 1. 生成挑战（低难度）
        double difficulty = 1000.0;
        PowChallenge challenge = generator.generate(difficulty);
        
        assertNotNull(challenge);
        assertNotNull(challenge.getToken());
        assertNotNull(challenge.getTargetHex());
        assertEquals(64, challenge.getTargetHex().length());
        
        log.info("Generated challenge: {}", challenge);
        
        // 2. 客户端求解
        PowSolution solution = solver.solve(challenge.getToken(), 10_000_000L);
        assertNotNull("未找到解", solution);
        
        // 3. 服务端验证
        boolean valid = verifier.verify(solution);
        
        assertTrue("Verification failed", valid);
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 测试不同难度级别
     */
    @Test
    public void testDifferentDifficulties() {
        log.info("=== Test: Different Difficulties ===");
        
        double[] difficulties = {100, 1000, 10000};
        
        for (double difficulty : difficulties) {
            log.info("Testing difficulty: {}", difficulty);
            
            PowChallenge challenge = generator.generate(difficulty);
            PowSolution solution = solver.solve(challenge.getToken(), 50_000_000L);
            
            assertNotNull("Failed at difficulty " + difficulty, solution);
            log.info("Solved difficulty {} with nonce {}", difficulty, solution.getNonce());
        }
        
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 测试防重放攻击
     */
    @Test
    public void testReplayProtection() {
        log.info("=== Test: Replay Protection ===");
        
        // 1. 首次提交
        PowChallenge challenge = generator.generate(1000.0);
        PowSolution solution = solver.solve(challenge.getToken(), 10_000_000L);
        
        assertTrue("First submission should succeed", verifier.verify(solution));
        
        // 2. 重放攻击（使用相同 Token）
        try {
            verifier.verify(solution);
            fail("Replay attack should be detected");
        } catch (PowException e) {
            assertTrue(e.getMessage().contains("replay attack"));
            log.info("Replay attack correctly detected: {}", e.getMessage());
        }
        
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 测试 JWT 签名篡改检测
     */
    @Test
    public void testSignatureTampering() {
        log.info("=== Test: Signature Tampering Detection ===");
        
        PowChallenge challenge = generator.generate(1000.0);
        String originalToken = challenge.getToken();
        
        // 篡改 Token（修改最后几个字符）
        String tamperedToken = originalToken.substring(0, originalToken.length() - 5) + "AAAAA";
        
        PowSolution originalSolution = solver.solve(originalToken, 10_000_000L);
        PowSolution tamperedSolution = new PowSolution(tamperedToken, originalSolution.getNonce(), 
                originalSolution.getAttempts(), originalSolution.getTimeMillis());
        
        try {
            verifier.verify(tamperedSolution);
            fail("Tampered signature should be detected");
        } catch (PowException e) {
            assertTrue(e.getMessage().contains("signature"));
            log.info("Signature tampering correctly detected: {}", e.getMessage());
        }
        
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 测试过期挑战
     */
    @Test
    public void testExpiredChallenge() throws InterruptedException {
        log.info("=== Test: Expired Challenge ===");
        
        // 创建 1 秒过期的生成器
        PowChallengeGenerator shortLivedGenerator = 
                new PowChallengeGenerator(SECRET_KEY, 1000L);
        
        PowChallenge challenge = shortLivedGenerator.generate(100.0);
        PowSolution solution = solver.solve(challenge.getToken(), 10_000_000L);
        
        // 等待过期
        Thread.sleep(1500);
        
        try {
            verifier.verify(solution);
            fail("Expired challenge should be rejected");
        } catch (PowException e) {
            assertTrue(e.getMessage().contains("expired"));
            log.info("Expired challenge correctly rejected: {}", e.getMessage());
        }
        
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 测试错误的 Nonce
     */
    @Test
    public void testInvalidNonce() {
        log.info("=== Test: Invalid Nonce ===");
        
        PowChallenge challenge = generator.generate(1000.0);
        
        // 使用错误的 Nonce
        PowSolution invalidSolution = new PowSolution(challenge.getToken(), 123456789L, 123456789L, 0L);
        
        boolean valid = verifier.verify(invalidSolution);
        assertFalse("Invalid nonce should fail verification", valid);
        
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 测试并发场景
     */
    @Test
    public void testConcurrency() throws InterruptedException {
        log.info("=== Test: Concurrency ===");
        
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        final boolean[] results = new boolean[threadCount];
        
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    PowChallenge challenge = generator.generate(1000.0);
                    PowSolution solution = solver.solve(challenge.getToken(), 10_000_000L);
                    results[index] = verifier.verify(solution);
                } catch (Exception e) {
                    log.error("Thread {} failed", index, e);
                    results[index] = false;
                }
            });
            threads[i].start();
        }
        
        // 等待所有线程完成
        for (Thread thread : threads) {
            thread.join();
        }
        
        // 验证所有结果
        for (int i = 0; i < threadCount; i++) {
            assertTrue("Thread " + i + " failed", results[i]);
        }
        
        log.info("All {} threads succeeded", threadCount);
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 性能基准测试
     */
    @Test
    public void testPerformanceBenchmark() {
        log.info("=== Test: Performance Benchmark ===");
        
        // 测试验证性能（每次生成新的挑战以避免重放检测）
        int iterations = 100;
        long totalNanos = 0;
        
        for (int i = 0; i < iterations; i++) {
            PowChallenge challenge = generator.generate(100.0);
            PowSolution solution = solver.solve(challenge.getToken(), 10_000_000L);
            
            long startTime = System.nanoTime();
            verifier.verify(solution);
            totalNanos += System.nanoTime() - startTime;
        }
        
        double avgMicros = (totalNanos / 1000.0) / iterations;
        
        log.info("Verification performance: {} iterations, avg: {}μs per verification",
                iterations, String.format("%.2f", avgMicros));
        
        assertTrue("Verification should be fast (< 5ms)", avgMicros < 5000);
        log.info("=== Test PASSED ===\n");
    }

    /**
     * 内存中的防重放实现（测试用）
     */
    static class InMemoryReplayProtection implements PowChallengeVerifier.ReplayProtection {
        
        private final Set<String> usedJtis = ConcurrentHashMap.newKeySet();

        @Override
        public boolean isUsed(String jti) {
            return usedJtis.contains(jti);
        }

        @Override
        public void markAsUsed(String jti, long expiration) {
            usedJtis.add(jti);
            // TODO: 生产环境需要定期清理过期的 JTI
        }
        
        public void reset() {
            usedJtis.clear();
        }
    }
}
