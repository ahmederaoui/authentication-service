package ma.enset.authenticatedservice.security;

public class JWTUtil {
    public static final String SECRET = "eraouisecret2001";
    public static final String AUTH_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 4*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN = 20*60*1000;
}
