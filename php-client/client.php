#!/usr/bin/env php
<?php
require __DIR__ . '/vendor/autoload.php';

use WebSocket\Client;

$room = $argv[1] ?? "general";
$ws = new Client("ws://127.0.0.1:3000/ws/$room", ['timeout' => 60000]);

echo "Connected to room: $room\n";

// start a background reader
$pid = pcntl_fork();
if ($pid === 0) {
    // child process: just read messages
    while (true) {
        try {
            $msg = $ws->receive();
            echo "[room:$room] $msg\n";
        } catch (Exception $e) {
            echo "Connection closed: {$e->getMessage()}\n";
            exit;
        }
    }
    exit;
}

// parent process: read from stdin and send
while (true) {
    $line = trim(fgets(STDIN));
    if ($line === "quit") {
        break;
    }
    try {
        $ws->send($line);
    } catch (Exception $e) {
        echo "Send failed: {$e->getMessage()}\n";
        break;
    }
}

$ws->close();
