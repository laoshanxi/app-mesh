#include "WebSocketClient.h"
#include <csignal>
#include <iostream>

static bool keep_running = true;

void signal_handler(int signal)
{
    keep_running = false;
}

int main()
{
    signal(SIGINT, signal_handler);

    WebSocket::Client client;

    // Configure connection
    WebSocket::ConnectionConfig config;
    config.address = "echo.websocket.org";
    config.path = "/";
    config.port = 443;
    config.use_ssl = true;
    config.protocol_name = "echo-protocol";

    client.setConfig(config);

    // Set up callbacks
    client.onConnect([]()
                     { std::cout << "Connected to server" << std::endl; });

    client.onDisconnect([]()
                        { std::cout << "Disconnected from server" << std::endl; });

    client.onMessage([](const uint8_t *data, size_t length, bool is_binary)
                     {
        if (is_binary) {
            std::cout << "Received binary message (" << length << " bytes)" << std::endl;
        } else {
            std::string msg(reinterpret_cast<const char*>(data), length);
            std::cout << "Received: " << msg << std::endl;
        } });

    client.onError([](const std::string &error)
                   { std::cerr << "Error: " << error << std::endl; });

    // Connect
    if (!client.connect())
    {
        std::cerr << "Failed to connect" << std::endl;
        return 1;
    }

    // Run event loop in background
    client.runAsync();

    // Wait for connection
    while (!client.isConnected() && keep_running)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Send messages
    if (client.isConnected())
    {
        client.sendText("Hello, WebSocket!");

        // Send more messages
        for (int i = 0; i < 5 && keep_running; i++)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            client.sendText("Message " + std::to_string(i));
        }
    }

    // Keep running until interrupted
    while (keep_running && client.isConnected())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    client.stop();
    client.disconnect();

    return 0;
}