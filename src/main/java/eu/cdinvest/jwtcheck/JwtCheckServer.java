package eu.cdinvest.jwtcheck;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Properties;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import org.apache.commons.io.FileUtils;

import org.json.JSONObject;

public class JwtCheckServer {

    public static void main(String[] args) throws Exception {
        int port = 10905;
                

        try (InputStream input = new FileInputStream("config.properties")) {

            Properties prop = new Properties();
            prop.load(input);
            port = Integer.parseInt(prop.getProperty("port"));
      
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        try {

            if (args.length > 0) {
                port = Integer.parseInt(args[0]);
            }

            HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

            server.createContext("/checkjwt", new CheckJwtRouter());
            server.createContext("/getjwk", new GetJwkRouter());

            server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(10));
            server.start();

            System.out.println("Server is listening on port " + port);
            JwtLogger.add("Server is listening on port " + port);
        } catch (Exception e) {
            JwtLogger.add("Failed to start server. Port may be in use.");
            return;
        }
    };

    static class GetJwkRouter implements HttpHandler {

        @Override
        public void handle(HttpExchange t) throws IOException {

            String jwkFile = null;
            StringBuilder username = new StringBuilder();
            String jwt = null;

            try (InputStream input = new FileInputStream("config.properties")) {

                Properties prop = new Properties();
                prop.load(input);
                jwkFile = prop.getProperty("jwkfile");

                File jwkf = new File(jwkFile);
                String charset = null;
                String jwkContent = FileUtils.readFileToString(jwkf, charset);

                JSONObject jsonOut = new JSONObject(jwkContent);

                JwtCheckServer.sendJsonOut(t, 200, jsonOut);
          
            } catch (IOException ex) {
                JSONObject jsonOut = new JSONObject();
                JwtCheckServer.sendJsonOut(t, 404, jsonOut);
            }
           
        }

    }

    static class CheckJwtRouter implements HttpHandler {

        @Override
        public void handle(HttpExchange t) throws IOException {

            StringBuilder username = new StringBuilder();
            String jwt = null;

            JSONObject jsonOut = new JSONObject();

            String method = t.getRequestMethod();

            switch (method) {
                case "GET":
                    Map<String, String> params = queryToMap(t.getRequestURI().getQuery());
                    jwt = params.get("jwt");
                    break;
                case "POST":
                    InputStream body = t.getRequestBody();

                    StringBuilder stringBuilder = new StringBuilder();
                    BufferedReader bufferedReader = null;

                    try {
                        if (body != null) {
                            bufferedReader = new BufferedReader(new InputStreamReader(body));
                            char[] charBuffer = new char[128];
                            int bytesRead = -1;
                            while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                                stringBuilder.append(charBuffer, 0, bytesRead);
                            }
                        }
                        jwt = stringBuilder.toString();
                    } catch (Exception e) {
                    } finally {
                        if (bufferedReader != null) {
                            try {
                                bufferedReader.close();
                            } catch (IOException ex) {
                            }
                        }
                    }
            }
            ;

            JwtLogger.add("New request. JWT = " + jwt);

            switch (JwtCheck.validate(jwt, username)) {
                case JWT_VALID:
                    JwtLogger.add("Request is valid.");
                    JwtLogger.add("User = " + username);

                    jsonOut.put("valid", true);
                    jsonOut.put("sub", username);
                    jsonOut.put("userid", username.toString().split("@")[0]);
                    JwtCheckServer.sendJsonOut(t, 200, jsonOut);
                    break;
                case JWT_EXPIRED:
                    JwtLogger.add("Token is expired");
                    JwtLogger.add("User = " + username);

                    jsonOut.put("valid", false);
                    jsonOut.put("reason", "Expired");
                    jsonOut.put("sub", username);
                    jsonOut.put("userid", username.toString().split("@")[0]);
                    JwtCheckServer.sendJsonOut(t, 401, jsonOut);
                    break;
                case JWT_INVALID:
                    JwtLogger.add("Request is invalid.");
                    JwtLogger.add("User = " + username);

                    jsonOut.put("valid", false);
                    jsonOut.put("reason", "Invalid token");
                    jsonOut.put("sub", username);
                    jsonOut.put("userid", username.toString().split("@")[0]);
                    JwtCheckServer.sendJsonOut(t, 401, jsonOut);
            }

        }
    };

    static Map<String, String> queryToMap(String query) {
        if (query == null) {
            return null;
        }
        Map<String, String> result = new HashMap<>();
        for (String param : query.split("&")) {
            String[] entry = param.split("=");
            if (entry.length > 1) {
                result.put(entry[0], entry[1]);
            } else {
                result.put(entry[0], "");
            }
        }
        return result;
    };

    static void sendJsonOut(HttpExchange t, int statuscode, JSONObject jsonOut) {
        try {
            String response = jsonOut.toString();
            t.getResponseHeaders().set("Content-Type", "application/json");
            t.sendResponseHeaders(statuscode, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        } catch (IOException e) {
        }

    };

}
