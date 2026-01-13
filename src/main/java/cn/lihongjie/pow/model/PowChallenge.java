package cn.lihongjie.pow.model;

import java.util.Date;

/**
 * PoW Challenge 数据模型
 * 
 * <p>核心 Payload 结构：
 * <ul>
 *   <li>iat: Issued At - 签发时间戳</li>
 *   <li>exp: Expiration - 过期时间戳</li>
 *   <li>jti: JWT ID - 唯一标识符（用于防重放）</li>
 *   <li>salt: 随机盐值（增加暴力破解成本）</li>
 *   <li>tgt: Target Threshold - 十六进制目标阈值</li>
 * </ul>
 * 
 * <p>数学模型：$Target = \frac{2^{256} - 1}{DifficultyFactor}$
 * 
 * @author lihongjie
 */
public class PowChallenge {
    
    /**
     * 签发时间（秒级时间戳）
     */
    private final Long issuedAt;
    
    /**
     * 过期时间（秒级时间戳）
     */
    private final Long expiration;
    
    /**
     * JWT 唯一标识符，用于防重放攻击
     * 推荐使用 UUID 或 Snowflake ID
     */
    private final String jwtId;
    
    /**
     * 随机盐值（Base64 或 Hex 编码）
     * 增加预计算攻击的成本
     */
    private final String salt;
    
    /**
     * 目标阈值（64 位十六进制字符串）
     * 验证条件：SHA-256(JWT + Solution) < Target
     */
    private final String targetHex;
    
    /**
     * 签名后的完整 JWT Token
     */
    private final String token;

    private PowChallenge(Builder builder) {
        this.issuedAt = builder.issuedAt;
        this.expiration = builder.expiration;
        this.jwtId = builder.jwtId;
        this.salt = builder.salt;
        this.targetHex = builder.targetHex;
        this.token = builder.token;
    }

    public Long getIssuedAt() {
        return issuedAt;
    }

    public Long getExpiration() {
        return expiration;
    }

    public String getJwtId() {
        return jwtId;
    }

    public String getSalt() {
        return salt;
    }

    public String getTargetHex() {
        return targetHex;
    }

    public String getToken() {
        return token;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Long issuedAt;
        private Long expiration;
        private String jwtId;
        private String salt;
        private String targetHex;
        private String token;

        public Builder issuedAt(Long issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public Builder expiration(Long expiration) {
            this.expiration = expiration;
            return this;
        }

        public Builder jwtId(String jwtId) {
            this.jwtId = jwtId;
            return this;
        }

        public Builder salt(String salt) {
            this.salt = salt;
            return this;
        }

        public Builder targetHex(String targetHex) {
            this.targetHex = targetHex;
            return this;
        }

        public Builder token(String token) {
            this.token = token;
            return this;
        }

        public PowChallenge build() {
            return new PowChallenge(this);
        }
    }

    @Override
    public String toString() {
        return "PowChallenge{" +
                "issuedAt=" + issuedAt +
                ", expiration=" + expiration +
                ", jwtId='" + jwtId + '\'' +
                ", salt='" + salt + '\'' +
                ", targetHex='" + targetHex + '\'' +
                ", token='" + token + '\'' +
                '}';
    }
}
