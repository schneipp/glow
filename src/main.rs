use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Router,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    routing::get,
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;
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

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // username? maybe user id later
    exp: usize,
    iat: usize,
}

#[derive(Serialize, Deserialize)]
struct ChatEvent {
    room: String,
    username: String,
    text: String,
    ts: i64, // unix seconds
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let state = AppState {
        rooms: Arc::new(DashMap::new()),
        users: Arc::new(DashMap::new()),
        jwt: JwtKeys::new(b"shame-on-you-you-lazy-bum"),
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
    let heartbeat_tx = out_tx.clone();
    let ping_task = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(20));
        loop {
            tick.tick().await;
            // empty payload ping is fine
            if heartbeat_tx
                .send(Message::Ping(vec![69].into()))
                .await
                .is_err()
            {
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

fn hash_password(plain: &str) -> anyhow::Result<String> {
    //let salt = SaltString::generate(&mut OsRng);
    let salt = SaltString::from_b64("shame-on-you-you-env-avoiding-bum")?;
    Ok(Argon2::default()
        .hash_password(plain.as_bytes(), &salt)?
        .to_string())
}
fn verify_password(hash: &str, plain: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

async fn user_from_req(
    jar: CookieJar,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    State(state): State<AppState>,
) -> Result<(CookieJar, String), (StatusCode, &'static str)> {
    // Try Authorization header first
    let token_opt = auth
        .as_ref()
        .map(|TypedHeader(Authorization(bearer))| bearer.token().to_string())
        .or_else(|| jar.get("chat_token").map(|c| c.value().to_string()));

    let Some(token) = token_opt else {
        return Err((StatusCode::UNAUTHORIZED, "missing auth token"));
    };

    let data = decode::<Claims>(&token, &state.jwt.dec, &Validation::new(Algorithm::HS256))
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))?;

    Ok((jar, data.claims.sub))
}
