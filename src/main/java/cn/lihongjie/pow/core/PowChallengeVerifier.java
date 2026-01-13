package cn.lihongjie.pow.core;

import cn.lihongjie.pow.exception.PowException;
import cn.lihongjie.pow.model.PowSolution;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

/**
 * JWT PoW Challenge 验证器（极致轻量化设计）
 * 
 * <p><b>核心算法</b>：
 * <pre>
 * 验证条件：SHA-256(JWT + Nonce) < Target
 * </pre>
 * 
 * <p><b>性能优化</b>：
 * <ul>
 *   <li>字节数组比对（避免 BigInteger 运算）</li>
 *   <li>单次哈希计算</li>
 *   <li>无反序列化开销</li>
 * </ul>
 * 
 * <p><b>安全检查链</b>：
 * <ol>
 *   <li>JWT 签名验证</li>
 *   <li>TTL 过期检查</li>
 *   <li>JTI 防重放检查（需外部实现）</li>
 *   <li>PoW 哈希验证</li>
 * </ol>
 * 
 * @author lihongjie
 */
public class PowChallengeVerifier {
    
    private static final Logger log = LoggerFactory.getLogger(PowChallengeVerifier.class);
    
    private final SecretKey secretKey;
    private final ReplayProtection replayProtection;

    /**
     * 构造函数
     * 
     * @param secret JWT 签名密钥（必须与生成器一致）
     * @param replayProtection 防重放检查接口（可为 null）
     */
    public PowChallengeVerifier(String secret, ReplayProtection replayProtection) {
        Objects.requireNonNull(secret, "Secret key cannot be null");
        if (secret.length() < 32) {
            throw new IllegalArgumentException(
                "Secret key must be at least 256 bits (32 characters)");
        }
        
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.replayProtection = replayProtection;
    }

    /**
     * 无防重放保护的构造函数（仅用于测试）
     */
    public PowChallengeVerifier(String secret) {
        this(secret, null);
    }

    /**
     * 验证 PoW Solution（不校验 context）
     * 
     * @param solution 客户端提交的解决方案
     * @return true 如果验证通过
     * @throws PowException 如果验证失败
     */
    public boolean verify(PowSolution solution) {
        return verify(solution, null);
    }

    /**
     * 验证 PoW Solution（校验 context 一致性）
     * 
     * @param solution 客户端提交的解决方案
     * @param expectedContext 期望的业务上下文（需与生成时一致）
     * @return true 如果验证通过
     * @throws PowException 如果验证失败或 context 不一致
     */
    public boolean verify(PowSolution solution, Map<String, Object> expectedContext) {
        Objects.requireNonNull(solution, "Solution cannot be null");
        Objects.requireNonNull(solution.getToken(), "Token cannot be null");
        
        String token = solution.getToken();
        long nonce = solution.getNonce();
        
        try {
            // 1. 验证 JWT 签名并解析
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            
            // 2. 提取关键字段
            String jti = claims.get("jti", String.class);
            Long exp = claims.get("exp", Long.class);
            String targetHex = claims.get("tgt", String.class);
            
            Objects.requireNonNull(jti, "Missing 'jti' in JWT");
            Objects.requireNonNull(exp, "Missing 'exp' in JWT");
            Objects.requireNonNull(targetHex, "Missing 'tgt' in JWT");
            
            // 3. TTL 检查（冗余，但提高可读性）
            long now = System.currentTimeMillis() / 1000;
            if (now > exp) {
                log.warn("Challenge expired [jti={}, exp={}, now={}]", jti, exp, now);
                throw new PowException("Challenge has expired");
            }
            
            // 4. Context 一致性校验（如果提供了 expectedContext）
            if (expectedContext != null && !expectedContext.isEmpty()) {
                validateContext(claims, expectedContext);
            }
            
            // 5. JTI 防重放检查
            if (replayProtection != null) {
                if (replayProtection.isUsed(jti)) {
                    log.warn("Replay attack detected [jti={}]", jti);
                    throw new PowException("Challenge has already been used (replay attack)");
                }
            }
            
            // 6. 执行 PoW 验证（核心算法）
            boolean valid = verifyProofOfWork(token, nonce, targetHex);
            
            if (valid) {
                // 7. 标记为已使用（防重放）
                if (replayProtection != null) {
                    replayProtection.markAsUsed(jti, exp);
                }
                log.info("PoW verification SUCCESS [jti={}, nonce={}]", jti, nonce);
            } else {
                log.warn("PoW verification FAILED [jti={}, nonce={}]", jti, nonce);
            }
            
            return valid;
            
        } catch (ExpiredJwtException e) {
            log.warn("JWT expired: {}", e.getMessage());
            throw new PowException("Challenge has expired", e);
        } catch (SignatureException e) {
            log.error("JWT signature verification failed: {}", e.getMessage());
            throw new PowException("Invalid JWT signature", e);
        } catch (Exception e) {
            log.error("PoW verification error", e);
            throw new PowException("Verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * 执行 PoW 验证（轻量化实现）
     * 
     * <p>算法：$Hash(JWT \| Nonce) < Target$
     * 
     * <p>实现策略：
     * <ul>
     *   <li>使用字节数组比对（避免 BigInteger）</li>
     *   <li>大端序比较（从高位到低位）</li>
     * </ul>
     * 
     * @param token JWT Token
     * @param nonce Nonce 值
     * @param targetHex 目标阈值（64 字符十六进制）
     * @return true 如果哈希值小于目标阈值
     */
    private boolean verifyProofOfWork(String token, long nonce, String targetHex) {
        try {
            // 1. 计算 SHA-256(JWT + Nonce)
            String input = token + nonce;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            
            // 2. 目标阈值转字节数组
            byte[] targetBytes = hexToBytes(targetHex);
            
            // 3. 字节数组比对（无符号比较）
            boolean result = compareUnsignedByteArrays(hashBytes, targetBytes) < 0;
            
            if (log.isDebugEnabled()) {
                String hashHex = bytesToHex(hashBytes);
                log.debug("PoW Verification Detail:\n  Input: {}\n  Hash:  {}\n  Target: {}\n  Result: {}", 
                        input, hashHex, targetHex, result ? "PASS" : "FAIL");
            }
            
            return result;
            
        } catch (Exception e) {
            log.error("PoW computation failed", e);
            return false;
        }
    }

    /**
     * 校验 JWT 中的 context 与期望值是否一致
     * 
     * @param claims JWT Claims
     * @param expectedContext 期望的业务上下文
     * @throws PowException 如果 context 不一致
     */
    private void validateContext(Claims claims, Map<String, Object> expectedContext) {
        for (Map.Entry<String, Object> entry : expectedContext.entrySet()) {
            String key = entry.getKey();
            Object expectedValue = entry.getValue();
            
            // 跳过标准字段
            if (isReservedField(key)) {
                continue;
            }
            
            Object actualValue = claims.get(key);
            
            // 检查字段是否存在
            if (actualValue == null) {
                log.error("Context validation failed: missing field '{}'", key);
                throw new PowException(String.format(
                        "Context validation failed: missing field '%s'", key));
            }
            
            // 检查值是否一致
            if (!expectedValue.equals(actualValue)) {
                log.error("Context validation failed: field '{}' mismatch (expected={}, actual={})", 
                        key, expectedValue, actualValue);
                throw new PowException(String.format(
                        "Context validation failed: field '%s' mismatch (expected=%s, actual=%s)", 
                        key, expectedValue, actualValue));
            }
        }
        
        log.debug("Context validation SUCCESS: {} fields matched", expectedContext.size());
    }

    /**
     * 检查是否为保留字段
     * 
     * @param fieldName 字段名
     * @return true 如果是保留字段
     */
    private boolean isReservedField(String fieldName) {
        return "iat".equals(fieldName) 
                || "exp".equals(fieldName) 
                || "jti".equals(fieldName) 
                || "salt".equals(fieldName) 
                || "tgt".equals(fieldName)
                || "iss".equals(fieldName)
                || "sub".equals(fieldName)
                || "aud".equals(fieldName)
                || "nbf".equals(fieldName);
    }

    /**
     * 无符号字节数组比对（大端序）
     * 
     * @return -1 if a < b, 0 if a == b, 1 if a > b
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
        
        // 长度比对
        return Integer.compare(a.length, b.length);
    }

    /**
     * 防重放保护接口（需外部实现）
     * 
     * <p>推荐实现方案：
     * <ul>
     *   <li>Redis: SET jti "used" EX {exp - now}</li>
     *   <li>Memcached: add(jti, "used", ttl)</li>
     *   <li>数据库: INSERT INTO used_challenges (jti, exp) ...</li>
     * </ul>
     */
    public interface ReplayProtection {
        
        /**
         * 检查 JTI 是否已被使用
         * 
         * @param jti JWT ID
         * @return true 如果已使用
         */
        boolean isUsed(String jti);
        
        /**
         * 标记 JTI 为已使用
         * 
         * @param jti JWT ID
         * @param expiration 过期时间（秒级时间戳）
         */
        void markAsUsed(String jti, long expiration);
    }

    /**
     * Convert byte array to hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
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
