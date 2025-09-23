#!/usr/bin/env php
<?php
require __DIR__ . '/vendor/autoload.php';

use WebSocket\Client;
use GuzzleHttp\Client as Http;
use GuzzleHttp\Exception\ClientException;

$baseUrl = "http://127.0.0.1:3000";
$room     = $argv[1] ?? "general";
$username = $argv[2] ?? "bro".time();
$password = $argv[3] ?? "secret123";

function loginOrRegister(Http $http, string $baseUrl, string $username, string $password): string {
    // 1) Try login
    try {
        $res = $http->post("$baseUrl/api/login", [
            'json' => ['username' => $username, 'password' => $password],
        ]);
        $body = json_decode($res->getBody()->getContents(), true);
        if (!isset($body['token'])) {
            fwrite(STDERR, "Login response missing token\n");
            exit(1);
        }
        echo "Logged in as $username\n";
        return $body['token'];
    } catch (ClientException $e) {
        if ($e->getResponse() && $e->getResponse()->getStatusCode() !== 401) {
            fwrite(STDERR, "Login failed ({$e->getResponse()->getStatusCode()}): ".$e->getResponse()->getBody()."\n");
            exit(1);
        }
        echo "Login returned 401 — will try to register…\n";
    }

    // 2) Register
    try {
        $res = $http->post("$baseUrl/api/register", [
            'json' => ['username' => $username, 'password' => $password],
        ]);
        if ($res->getStatusCode() === 201) {
            echo "Registered user $username\n";
        }
    } catch (ClientException $e) {
        $code = $e->getResponse() ? $e->getResponse()->getStatusCode() : 0;
        if ($code === 409) {
            echo "User already exists; continuing to login…\n";
        } else {
            fwrite(STDERR, "Register failed ($code): ".$e->getResponse()->getBody()."\n");
            exit(1);
        }
    }

    // 3) Retry login
    try {
        $res = $http->post("$baseUrl/api/login", [
            'json' => ['username' => $username, 'password' => $password],
        ]);
        $body = json_decode($res->getBody()->getContents(), true);
        if (!isset($body['token'])) {
            fwrite(STDERR, "Login (after register) missing token\n");
            exit(1);
        }
        echo "Logged in as $username (after register)\n";
        return $body['token'];
    } catch (ClientException $e) {
        $code = $e->getResponse() ? $e->getResponse()->getStatusCode() : 0;
        fwrite(STDERR, "Login failed after register ($code): ".$e->getResponse()->getBody()."\n");
        exit(1);
    }
}

$http = new Http([
    'http_errors' => true, // we want exceptions for 4xx/5xx
    'timeout' => 10,
]);

$token = loginOrRegister($http, $baseUrl, $username, $password);

// Optional: show available channels before joining
try {
    $res = $http->get("$baseUrl/api/channels", [
        'headers' => ['Authorization' => "Bearer $token"],
    ]);
    $channels = json_decode($res->getBody()->getContents(), true)['channels'] ?? [];
    echo "Available channels: ".(empty($channels) ? "(none yet)" : implode(", ", $channels))."\n";
} catch (Exception $e) {
    echo "Could not fetch /api/channels (maybe no rooms yet): ".$e->getMessage()."\n";
}

// 4) Connect WebSocket with Authorization header
$ws = new Client("ws://127.0.0.1:3000/ws/$room", [
    'timeout' => 60000,
    'headers' => [
        'Authorization' => "Bearer $token",
    ],
]);

echo "Connected to room: $room as $username\n";

// background reader
$pid = function_exists('pcntl_fork') ? pcntl_fork() : -1;
if ($pid === 0) {
    // child: read loop
    while (true) {
        try {
            $msg = $ws->receive();
            $data = json_decode($msg, true);
            if (is_array($data) && isset($data['username'], $data['text'])) {
                $roomName = $data['room'] ?? $room;
                echo "[{$roomName}] {$data['username']}: {$data['text']}\n";
            } else {
                echo "[raw] $msg\n";
            }
        } catch (Exception $e) {
            echo "Connection closed: {$e->getMessage()}\n";
            exit;
        }
    }
    exit;
}

// parent: stdin -> send
while (true) {
    $line = fgets(STDIN);
    if ($line === false) break;
    $line = trim($line);
    if ($line === '' ) continue;
    if ($line === 'quit') break;
    try {
        $ws->send($line);
    } catch (Exception $e) {
        echo "Send failed: {$e->getMessage()}\n";
        break;
    }
}

$ws->close();
