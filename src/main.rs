use std::sync::Arc;
use std::time::Duration;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    routing::get,
    Router,
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;
use jsonwebtoken::{encode, decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tracing::info;
type RoomId = String;

#[derive(Clone)]
struct AppState {
    //Arc for shared ownership, DashMap for concurrent access
    // RoomId maps to a broadcast channel sender
    rooms: Arc<DashMap<RoomId, broadcast::Sender<String>>>,
    users: Arc<DashMap<String, String>>, // username -> password_hash
    jwt: JwtKeys,
}
#[derive(Clone)]
struct JwtKeys {
    enc: EncodingKey,
    dec: DecodingKey,
}
impl JwtKeys {
    fn new(secret: &[u8]) -> Self {
        Self {
            enc: EncodingKey::from_secret(secret),
            dec: DecodingKey::from_secret(secret),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let state = AppState {
        rooms: Arc::new(DashMap::new()),
    };

    let app = Router::new()
        .route("/ws/{room_id}", get(ws_handler))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn ws_handler(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, room_id))
}

async fn handle_socket(socket: WebSocket, state: AppState, room_id: String) {
    // get or create the room broadcaster
    let tx = state
        .rooms
        .entry(room_id.clone())
        .or_insert_with(|| broadcast::channel::<String>(1024).0)
        .clone();

    // subscribe for inbound fanout
    let mut rx = tx.subscribe();

    // outbound queue: anything the recv task (or others) want to send to this socket
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);
    // inside handle_socket, after creating `out_tx`
    let heartbeat_tx = out_tx.clone();
    let ping_task = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(20));
        loop {
            tick.tick().await;
            // empty payload ping is fine
            if heartbeat_tx.send(Message::Ping(vec![69].into())).await.is_err() {
                break; // socket gone
            }
        }
    });
    // split socket
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // task: forward room broadcasts and anything in out_rx -> this socket
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // room fanout (String -> Text)
                Ok(msg) = rx.recv() => {
                    if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                // explicit outbound messages (including Pong)
                Some(msg) = out_rx.recv() => {
                    if ws_sender.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // task: read this socket -> publish to room or queue control replies
    let recv_task = {
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_receiver.next().await {
                match msg {
                    Message::Text(text_bytes) => {
                        let text: String = text_bytes.as_str().into();
                        let _ = tx.send(text); // fan out to the room
                    }
                    Message::Ping(p) => {
                        // enqueue Pong via the outbound queue (so we don't need the sink here)
                        let _ = out_tx.send(Message::Pong(p)).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        })
    };

    let _ = tokio::join!(send_task, recv_task, ping_task);

    // cleanup: remove empty room
    if tx.receiver_count() == 0 {
        state.rooms.remove(&room_id);
    }
}
