package cn.lihongjie.pow.client;

import cn.lihongjie.pow.exception.PowException;
import cn.lihongjie.pow.model.PowChallenge;
import cn.lihongjie.pow.model.PowSolution;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * PoW Challenge 客户端求解器（高性能实现）
 * 
 * <p><b>算法</b>：穷举法寻找 Nonce，使得 $Hash(JWT \| Nonce) < Target$
 * 
 * <p><b>性能优化</b>：
 * <ul>
 *   <li>预解析 JWT（避免重复解析）</li>
 *   <li>复用 MessageDigest 实例</li>
 *   <li>字节数组比对（无大数运算）</li>
 *   <li>多线程支持（可选）</li>
 * </ul>
 * 
 * <p><b>客户端类型</b>：
 * <ul>
 *   <li>Java Server-Side: 使用此实现</li>
 *   <li>Browser JavaScript: 使用 Web Worker + crypto.subtle API</li>
 *   <li>Mobile Native: 使用平台原生哈希库</li>
 * </ul>
 * 
 * @author lihongjie
 */
public class PowChallengeSolver {
    
    private static final Logger log = LoggerFactory.getLogger(PowChallengeSolver.class);
    
    /**
     * 默认最大尝试次数（防止无限循环）
     */
    private static final long DEFAULT_MAX_ATTEMPTS = 100_000_000L;

    /**
     * 求解 PoW Challenge
     * 
     * @param token JWT Token
     * @param maxAttempts 最大尝试次数
     * @return PoW 解决方案（包含 nonce, attempts, time）
     * @throws PowException 如果超过最大尝试次数仍未找到解
     */
    public PowSolution solve(String token, long maxAttempts) {
        Objects.requireNonNull(token, "Token cannot be null");
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("Max attempts must be positive");
        }
        
        try {
            // 1. 预解析 JWT（无签名验证）
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT format");
            }
            
            // 从 Payload 提取 Target
            String payloadJson = new String(
                java.util.Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
            );
            
            // 简单解析（生产环境建议使用 JSON 库）
            String targetHex = extractTargetFromPayload(payloadJson);
            byte[] targetBytes = hexToBytes(targetHex);
            
            log.info("Starting PoW solving [target={}..., maxAttempts={}]", 
                    targetHex.substring(0, 16), maxAttempts);
            
            // 2. 穷举求解
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long startTime = System.currentTimeMillis();
            
            for (long nonce = 0; nonce < maxAttempts; nonce++) {
                String input = token + nonce;
                digest.reset();
                byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
                
                // 比对哈希值
                if (compareUnsignedByteArrays(hashBytes, targetBytes) < 0) {
                    long elapsedMs = System.currentTimeMillis() - startTime;
                    double hashRate = (nonce + 1) / (elapsedMs / 1000.0);
                    
                    log.info("PoW solution FOUND! [nonce={}, attempts={}, time={}ms, hashrate={}/s]",
                            nonce, nonce + 1, elapsedMs, String.format("%.2f", hashRate));
                    
                    return new PowSolution(token, nonce, nonce + 1, elapsedMs);
                }
                
                // 每 100 万次打印进度
                if (nonce > 0 && nonce % 1_000_000 == 0) {
                    log.debug("Progress: {} million attempts...", nonce / 1_000_000);
                }
            }
            
            log.warn("PoW solving FAILED: Reached max attempts ({})", maxAttempts);
            throw new PowException("Failed to find solution: max attempts (" + maxAttempts + ") reached");
            
        } catch (PowException e) {
            throw e;
        } catch (Exception e) {
            log.error("PoW solving error", e);
            throw new PowException("PoW solving error: " + e.getMessage(), e);
        }
    }

    /**
     * 使用默认最大尝试次数
     */
    public PowSolution solve(String token) {
        return solve(token, DEFAULT_MAX_ATTEMPTS);
    }

    /**
     * 从 Payload JSON 提取 Target（简化实现）
     * 
     * <p><b>生产环境建议</b>：使用 Jackson/Gson 解析
     */
    private String extractTargetFromPayload(String payloadJson) {
        // 查找 "tgt":"..." 模式
        String key = "\"tgt\":\"";
        int start = payloadJson.indexOf(key);
        if (start == -1) {
            throw new IllegalArgumentException("Missing 'tgt' in JWT payload");
        }
        
        start += key.length();
        int end = payloadJson.indexOf("\"", start);
        
        return payloadJson.substring(start, end);
    }

    /**
     * 无符号字节数组比对
     */
    private int compareUnsignedByteArrays(byte[] a, byte[] b) {
        int minLength = Math.min(a.length, b.length);
        
        for (int i = 0; i < minLength; i++) {
            int unsignedA = a[i] & 0xFF;
            int unsignedB = b[i] & 0xFF;
            
            if (unsignedA < unsignedB) {
                return -1;
            } else if (unsignedA > unsignedB) {
                return 1;
            }
        }
        
        return Integer.compare(a.length, b.length);
    }

    /**
     * 多线程求解（高级用法）
     * 
     * <p>原理：将 Nonce 空间分段，多个线程并行搜索
     * 
     * @param token JWT Token
     * @param maxAttempts 最大尝试次数
     * @param threadCount 线程数
     * @return PoW 解决方案
     */
    public PowSolution solveMultiThreaded(String token, long maxAttempts, int threadCount) {
        // TODO: 实现多线程版本
        // 提示：使用 ExecutorService + Future，每个线程搜索不同的 Nonce 范围
        throw new UnsupportedOperationException("Multi-threaded solving not implemented yet");
    }

    /**
     * Convert hex string to byte array
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
