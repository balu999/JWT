package com.PubSub2;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

public class UserClient {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        try {
            //Generating token here
            String token = generateToken(username, password);

            //Validating a Token here and getting User Details
            String userData = getUserDetails(token);
            System.out.println(userData);
        } catch (Exception e) {
            System.out.println("message:" + e.getMessage());
        }
    }

    private static String generateToken(String username,String password) throws Exception{
        try {
            URL url = new URL("http://localhost:8080/generate-token?username=" + username + "&password=" + password);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String response = reader.readLine();
                reader.close();
                JSONObject responseObject = new JSONObject(response);
                if(responseObject.getBoolean("isSuccess")) {
                    return responseObject.getString("token");
                } else {
                    throw new Exception(responseObject.getString("errMsg"));
                }
            } else {
                System.out.println("Failed to generate token. HTTP Response Code: " + responseCode);
            }
        } catch (IOException e) {
            throw e;
        }
        throw new Exception("Something is wrong...");
    }

    private static String getUserDetails(String token) throws Exception{
        try {
            URL url = new URL("http://localhost:8080/validate-token?token=" + token);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String response = reader.readLine();
                reader.close();
                JSONObject responseObject = new JSONObject(response);
                if(responseObject.getBoolean("isSuccess")) {
                    return responseObject.getString("userData");
                } else {
                    throw new Exception(responseObject.getString("errMsg"));
                }
            } else {
                System.out.println("Failed to validate token. HTTP Response Code: " + responseCode);
            }
        } catch (IOException e) {
            throw e;
        }
        throw new Exception("Something is wrong...");
    }
}
