package com.PubSub2;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;


public class UserServer {
    public static HashMap<String, String> userVsPwdMap = new HashMap<String, String>();
    public static HashMap<String, HashMap<String, String>> userNameVsDetails = new HashMap<>();
    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    static {
        userVsPwdMap.put("user1","password1");
        userVsPwdMap.put("user2","password2");
        userVsPwdMap.put("user3","password3");

        HashMap<String, String> user1Details = new HashMap<>();
        user1Details.put("FIRST_NAME", "User1FirstName");
        user1Details.put("LAST_NAME", "User1LastName");
        userNameVsDetails.put("user1", user1Details);

        HashMap<String, String> user2Details = new HashMap<>();
        user2Details.put("FIRST_NAME", "User2FirstName");
        user2Details.put("LAST_NAME", "User2LastName");
        userNameVsDetails.put("user2", user2Details);

        HashMap<String, String> user3Details = new HashMap<>();
        user3Details.put("FIRST_NAME", "User3FirstName");
        user3Details.put("LAST_NAME", "User3LastName");
        userNameVsDetails.put("user3", user3Details);
    }
    public static void main(String[] args) throws IOException {
        System.out.println("User Server...");

        int port = 8080;

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/generate-token", new GenerateTokenHandler());
        server.createContext("/validate-token", new ValidateTokenHandler());

        server.setExecutor(null);
        server.start();

        System.out.println("Server started on port " + port);
    }

    static class GenerateTokenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String queryString = exchange.getRequestURI().getQuery();
                Map<String, String> params = Utils.parseQueryString(queryString);

                String username = params.get("username");
                String password = params.get("password");

                JSONObject response = new JSONObject();

                try {
                    String token = isValidUser(username, password);
                    response.put("isSuccess", true);
                    response.put("token", token);
                } catch (Exception e) {
                    response.put("isSuccess", false);
                    response.put("errMsg", e.getMessage());
                }

                exchange.sendResponseHeaders(200, response.toString().length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.toString().getBytes());
                os.close();
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }

        private static String isValidUser(String username, String password) throws Exception{
            if(userVsPwdMap.containsKey(username)) {
                if(userVsPwdMap.get(username).equals(password)) {
                    return generateToken(username);
                }
            } else {
                throw new Exception("User does not exist");
            }
            throw new Exception("Invalid Credentials");
        }
    }

    static class ValidateTokenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String queryString = exchange.getRequestURI().getQuery();
                Map<String, String> params = Utils.parseQueryString(queryString);

                String token = params.get("token");

                try {
                    JSONObject response = new JSONObject();
                    try {
                        String userName = validateToken(token);
                        response.put("isSuccess", true);
                        response.put("userData", getUserData(userName));
                    } catch (Exception e) {
                        response.put("isSuccess", false);
                        response.put("errMsg", "Invalid Token");
                    }

                    exchange.sendResponseHeaders(200, response.toString().length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.toString().getBytes());
                    os.close();
                } catch (Exception e) {
                    exchange.sendResponseHeaders(401, -1); // Unauthorized
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }

        private static String validateToken(String token) {
            try {
                Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
                return claims.getBody().getSubject();
            } catch (Exception e) {
                throw e;
            }
        }
    }

    static class Utils {
        static Map<String, String> parseQueryString(String queryString) {
            Map<String, String> params = new HashMap<>();

            String[] pairs = queryString.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=");
                String key = keyValue[0];
                String value = keyValue.length > 1 ? keyValue[1] : "";
                params.put(key, value);
            }

            return params;
        }
    }

    public static String getUserData(String userName) {
        HashMap<String,String> userDetails = userNameVsDetails.get(userName);

        return "User Data for " + userName + " as follows FIRST NAME: " + userDetails.get("FIRST_NAME") +" AND LAST NAME: " + userDetails.get("LAST_NAME");
    }

    private static String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }
}
