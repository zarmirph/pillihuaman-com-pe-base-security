package pillihuaman.com.pe.lib.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import pillihuaman.com.pe.basebd.common.MyJsonWebToken;
import pillihuaman.com.pe.basebd.user.User;
import pillihuaman.com.pe.lib.response.ResponseUser;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;


    public JwtService() {
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(User userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            User userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(
            User userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            User userDetails,
            long expiration
    ) {
        Map<String, Object> claims = new HashMap<>();
        claims = createClaimsFromUser(userDetails);
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Map<String, Object> createClaimsFromUser(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        if (userDetails instanceof User) {

            User user = (User) userDetails;
            /*claims.put("email", user.getEmail());
            claims.put("mobilPhone", user.getMobilPhone());
            claims.put("alias", user.getAlias());
            claims.put("idSystem", user.getIdSystem());
            claims.put("id", user.getId().toHexString());*/


            // Map<String, Object> claims = new HashMap<>();

// Create a 'user' map to store user-related properties
            Map<String, Object> userMap = new HashMap<>();
            userMap.put("id", user.getId().toHexString());
            userMap.put("mobilPhone", user.getMobilPhone());
            userMap.put("email", user.getEmail());
            //userMap.put("sub", myToken.getSubject());
            userMap.put("alias", user.getAlias());

// Create an 'application' map to store application-related properties
            Map<String, Object> applicationMap = new HashMap<>();
            applicationMap.put("aplicationID", "1");

// Add the 'user' and 'application' maps to the 'claims' map
            claims.put("user", userMap);
            claims.put("application", applicationMap);

// Add 'iat' and 'exp' to the 'claims' map
            //claims.put("iat", myToken.getIssuedAt());
            //claims.put("exp", myToken.getExpiration());


        }
        return claims;
    }

    public MyJsonWebToken parseTokenToMyJsonWebToken(String token) {
        // Extraer el JWT de las cabeceras como "Bearer token"
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7); // Extrae solo el token
        }
        Claims claims = extractAllClaims(token); // Decodifica y obtiene los claims del token

        MyJsonWebToken myJsonWebToken = new MyJsonWebToken();

        // Extraer los datos de "user"
        Map<String, Object> userMap = (Map<String, Object>) claims.get("user");
        if (userMap != null) {
            ResponseUser user = new ResponseUser();

            // Convertir 'id' (idUser) de String a ObjectId
            String userId = (String) userMap.get("id");
            if (userId != null) {
                user.setId(new ObjectId(userId));
            }

            // Establecer otros atributos del usuario
            user.setMobilPhone((String) userMap.get("mobilPhone"));
            user.setMail((String) userMap.get("email"));
            user.setAlias((String) userMap.get("alias"));
            user.setUsername((String) userMap.get("userName"));
           // user.setEnabled((Boolean) claims.get("enabled") ? 1 : 0); // Convertir booleano a int si es necesario

            myJsonWebToken.setUser(user);
        }

        // Extraer los datos de "application"
        Map<String, Object> applicationMap = (Map<String, Object>) claims.get("application");
        if (applicationMap != null) {
            MyJsonWebToken.Aplication application = new MyJsonWebToken.Aplication();
            // Convertir 'aplicationID' de String a ObjectId
            String applicationId = (String) applicationMap.get("aplicationID");
           /* if (applicationId != null) {
                application.setAplicationID(new ObjectId(applicationId));
            }*/
           // application.setName((String) applicationMap.get("name"));
            //application.setMultiSession((String) applicationMap.get("multiSession"));
            myJsonWebToken.setAplication(application);
        }

        return myJsonWebToken;
    }


}

