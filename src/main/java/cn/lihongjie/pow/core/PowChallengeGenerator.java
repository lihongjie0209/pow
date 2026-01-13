package cn.lihongjie.pow.core;

import cn.lihongjie.pow.exception.PowException;
import cn.lihongjie.pow.model.PowChallenge;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * JWT PoW Challenge 生成器
 * 
 * <p><b>核心算法</b>：
 * <pre>
 * Target = (2^256 - 1) / DifficultyFactor
 * </pre>
 * 
 * <p><b>安全特性</b>：
 * <ul>
 *   <li>使用 HS256 签名保证 Payload 完整性</li>
 *   <li>JTI 防重放（需配合 Redis/DB）</li>
 *   <li>随机盐值防预计算攻击</li>
 *   <li>TTL 机制（默认 5 分钟）</li>
 * </ul>
 * 
 * @author lihongjie
 */
public class PowChallengeGenerator {
    
    private static final Logger log = LoggerFactory.getLogger(PowChallengeGenerator.class);
    
    /**
     * 最大目标值（2^256 - 1）
     */
    private static final BigInteger MAX_TARGET = new BigInteger("2").pow(256).subtract(BigInteger.ONE);
    
    /**
     * 盐值字节数
     */
    private static final int SALT_BYTES = 16;
    
    /**
     * 默认 TTL（毫秒）
     */
    private static final long DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 分钟
    
    private final SecretKey secretKey;
    private final SecureRandom secureRandom;
    private final long ttlMillis;

    /**
     * 构造函数
     * 
     * @param secret JWT 签名密钥（≥256 bit）
     * @param ttlMillis Challenge 有效期（毫秒）
     */
    public PowChallengeGenerator(String secret, long ttlMillis) {
        Objects.requireNonNull(secret, "Secret key cannot be null");
        if (secret.length() < 32) {
            throw new IllegalArgumentException(
                "Secret key must be at least 256 bits (32 characters)");
        }
        if (ttlMillis <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }
        
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.secureRandom = new SecureRandom();
        this.ttlMillis = ttlMillis;
    }

    /**
     * 使用默认 TTL（5 分钟）
     */
    public PowChallengeGenerator(String secret) {
        this(secret, DEFAULT_TTL_MS);
    }

    /**
     * 生成 PoW Challenge（不含额外上下文）
     * 
     * @param difficultyFactor 难度因子（≥1.0）
     *                         - 1.0: 最简单（几乎秒解）
     *                         - 1000: 低难度（毫秒级）
     *                         - 1000000: 中等难度（秒级）
     *                         - 1000000000: 高难度（分钟级）
     * @return PowChallenge 对象
     * @throws PowException 如果参数非法
     */
    public PowChallenge generate(double difficultyFactor) {
        return generate(difficultyFactor, null);
    }

    /**
     * 生成 PoW Challenge（支持业务上下文）
     * 
     * @param difficultyFactor 难度因子（≥1.0）
     * @param context 业务上下文参数（可选）
     *                - userId: 用户ID
     *                - apiPath: 接口地址
     *                - clientIp: 客户端IP
     *                - 其他自定义业务字段
     * @return PowChallenge 对象
     * @throws PowException 如果参数非法
     */
    public PowChallenge generate(double difficultyFactor, Map<String, Object> context) {
        if (difficultyFactor < 1.0) {
            throw new IllegalArgumentException(
                "Difficulty factor must be >= 1.0");
        }
        
        try {
            // 1. 计算 Target Hex
            String targetHex = calculateTargetHex(difficultyFactor);
            log.debug("Calculated target hex for difficulty {}: {}", difficultyFactor, targetHex);
            
            // 2. 生成 Payload 元素
            long now = System.currentTimeMillis();
            long iat = now / 1000;
            long exp = (now + ttlMillis) / 1000;
            String jti = UUID.randomUUID().toString();
            String salt = generateSalt();
            
            // 3. 构建 JWT Payload（包含标准字段 + 业务上下文）
            io.jsonwebtoken.JwtBuilder builder = Jwts.builder()
                    .claim("iat", iat)
                    .claim("exp", exp)
                    .claim("jti", jti)
                    .claim("salt", salt)
                    .claim("tgt", targetHex);
            
            // 4. 添加业务上下文参数（可选，过滤标准字段）
            if (context != null && !context.isEmpty()) {
                // 过滤掉JWT标准字段，防止覆盖
                context.entrySet().stream()
                        .filter(entry -> !isReservedField(entry.getKey()))
                        .forEach(entry -> builder.claim(entry.getKey(), entry.getValue()));
                log.debug("Added {} context claims to JWT (filtered reserved fields)", 
                        context.entrySet().stream().filter(e -> !isReservedField(e.getKey())).count());
            }
            
            // 5. 签名 JWT
            String token = builder
                    .signWith(secretKey, SignatureAlgorithm.HS256)
                    .compact();
            
            log.info("Generated PoW challenge [jti={}, difficulty={}, target={}, context={}]", 
                    jti, difficultyFactor, targetHex.substring(0, 16) + "...", 
                    context != null ? context.keySet() : "none");
            
            return PowChallenge.builder()
                    .issuedAt(iat)
                    .expiration(exp)
                    .jwtId(jti)
                    .salt(salt)
                    .targetHex(targetHex)
                    .token(token)
                    .build();
            
        } catch (Exception e) {
            throw new PowException("Failed to generate PoW challenge", e);
        }
    }

    /**
     * 检查是否为保留字段（不允许 context 覆盖）
     * 
     * @param fieldName 字段名
     * @return true 如果是保留字段
     */
    private boolean isReservedField(String fieldName) {
        // JWT 标准字段 + PoW 自定义字段
        return "iat".equals(fieldName) 
                || "exp".equals(fieldName) 
                || "jti".equals(fieldName) 
                || "salt".equals(fieldName) 
                || "tgt".equals(fieldName)
                || "iss".equals(fieldName)  // JWT 标准 Issuer
                || "sub".equals(fieldName)  // JWT 标准 Subject
                || "aud".equals(fieldName)  // JWT 标准 Audience
                || "nbf".equals(fieldName); // JWT 标准 Not Before
    }

    /**
     * 计算目标阈值（十六进制字符串）
     * 
     * <p>算法：$Target = \left\lfloor \frac{2^{256} - 1}{DifficultyFactor} \right\rfloor$
     * 
     * @param difficultyFactor 难度因子
     * @return 64 字符的十六进制字符串（小写，无 0x 前缀）
     */
    private String calculateTargetHex(double difficultyFactor) {
        // 使用 BigDecimal 提高精度
        BigInteger factor = BigInteger.valueOf((long) difficultyFactor);
        
        // 如果 difficultyFactor 有小数部分，需要特殊处理
        if (difficultyFactor != Math.floor(difficultyFactor)) {
            // 转换为分数运算以保持精度
            long multiplier = 1_000_000_000L; // 10^9 精度
            BigInteger numerator = MAX_TARGET.multiply(BigInteger.valueOf(multiplier));
            BigInteger denominator = BigInteger.valueOf((long)(difficultyFactor * multiplier));
            factor = numerator.divide(denominator);
        } else {
            factor = MAX_TARGET.divide(factor);
        }
        
        // 转换为 64 字节十六进制字符串（补零）
        String hex = factor.toString(16);
        return padHexTo64Chars(hex);
    }

    /**
     * 生成随机盐值
     */
    private String generateSalt() {
        byte[] saltBytes = new byte[SALT_BYTES];
        secureRandom.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
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
     * 补零到 64 字符
     */
    private String padHexTo64Chars(String hex) {
        if (hex.length() >= 64) {
            return hex.substring(0, 64);
        }
        StringBuilder sb = new StringBuilder(64);
        for (int i = 0; i < 64 - hex.length(); i++) {
            sb.append('0');
        }
        sb.append(hex);
        return sb.toString();
    }
}
